#include "DisassemblyModel.h"
#include <ghidra/ProgramDB.h>
#include <ghidra/DecompInterface.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Address.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/FunctionIterator.h>
#include <ghidra/Function.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SymbolIterator.h>
#include <ghidra/Symbol.h>
#include <ghidra/SymbolType.h>
#include <algorithm>
#include <set>

void DisassemblyModel::clear() {
    rows_.clear();
    addressToRow_.clear();
    lengthByAddress_.clear();
    blocks_.clear();
    instrCount_ = 0;
}

void DisassemblyModel::buildIndex(ghidra::ProgramDB* program, ghidra::DecompInterface* decomp) {
    clear();
    if (!program || !decomp || !decomp->isOpen())
        return;

    auto* mem = program->getMemory();
    auto* af = program->getAddressFactory();
    auto* fm = program->getFunctionManager();
    auto* st = program->getSymbolTable();
    if (!mem || !af) return;

    auto allBlocks = mem->getBlocks();
    if (allBlocks.empty()) return;

    auto isInExecBlock = [&](uint64_t addr) -> bool {
        for (auto* b : allBlocks) {
            if (!b) continue;
            if (!(b->getFlags() & ghidra::MemoryBlock::FLAG_EXECUTE)) continue;
            uint64_t bs = b->getStart().getUnsignedOffset();
            if (addr >= bs && addr < bs + b->getSize()) return true;
        }
        return false;
    };

    // --- Collect known functions from FunctionManager ---
    std::vector<FuncInfo> functions;
    std::set<uint64_t> coveredAddresses;
    if (fm) {
        ghidra::FunctionIterator fit = fm->getFunctions(true);
        while (fit.hasNext()) {
            ghidra::Function* func = fit.next();
            if (!func) continue;
            ghidra::Address bodyMin = func->getBody().getMinAddress();
            ghidra::Address bodyMax = func->getBody().getMaxAddress();
            if (!bodyMin.isValid() || !bodyMax.isValid()) continue;
            uint64_t entry = func->getEntryPoint().getUnsignedOffset();
            uint64_t bStart = bodyMin.getUnsignedOffset();
            uint64_t bEnd = bodyMax.getUnsignedOffset();
            functions.push_back({ entry, bStart, bEnd, QString::fromStdString(func->getName()) });
            for (uint64_t a = bStart; a <= bEnd; ++a)
                coveredAddresses.insert(a);
        }
    }

    // --- Add exports/symbols not yet covered as discovered functions ---
    if (st) {
        ghidra::SymbolIterator sit = st->getAllProgramSymbols(true);
        while (sit.hasNext()) {
            ghidra::Symbol* sym = sit.next();
            if (!sym) continue;
            if (sym->getSymbolType() == ghidra::SymbolType::NAMESPACE ||
                sym->getSymbolType() == ghidra::SymbolType::CLASS ||
                sym->getSymbolType() == ghidra::SymbolType::LIBRARY)
                continue;
            uint64_t addr = sym->getAddress().getUnsignedOffset();
            if (addr == 0 || !isInExecBlock(addr)) continue;
            if (coveredAddresses.count(addr)) continue;
            QString name = QString::fromStdString(sym->getName());
            if (name.isEmpty())
                name = QString("sub_0x%1").arg(addr, 0, 16);
            functions.push_back({ addr, addr, addr + 0xFF, name });
            for (uint64_t a = addr; a <= addr + 0xFF; ++a)
                coveredAddresses.insert(a);
        }
    }

    // Sort by entry
    std::sort(functions.begin(), functions.end(),
        [](const FuncInfo& a, const FuncInfo& b) { return a.entry < b.entry; });

    // --- Walk each function body via instruction lengths ---
    std::set<uint64_t> seenInstructionAddresses;
    std::vector<DisasmRow> instructionAndHeaderRows;

    for (const auto& func : functions) {
        uint64_t disasmEnd = func.bodyEnd;
        if (disasmEnd >= func.entry + 0x1000) disasmEnd = func.entry + 0x1000; // cap at 4KB

        bool emittedHeader = false;
        uint64_t addr = func.entry;
        while (addr <= disasmEnd) {
            int len = 0;
            try {
                len = decomp->instructionLengthAt(addr);
            } catch (...) {
                ++addr;
                continue;
            }
            if (len <= 0) {
                ++addr;
                continue;
            }
            if (seenInstructionAddresses.count(addr)) {
                addr += len;
                continue;
            }
            if (!emittedHeader) {
                DisasmRow header;
                header.kind = DisasmRow::Kind::FunctionHeader;
                header.address = func.entry;
                header.text = func.name;
                instructionAndHeaderRows.push_back(header);
                emittedHeader = true;
            }
            DisasmRow row;
            row.kind = DisasmRow::Kind::Instruction;
            row.address = addr;
            row.length = len;
            instructionAndHeaderRows.push_back(row);
            seenInstructionAddresses.insert(addr);
            lengthByAddress_[addr] = len;
            addr += len;
        }
    }

    // --- Analyze uncovered data gaps in executable blocks ---
    std::vector<DisasmRow> gapRows;
    auto getBlockBytes = [&](uint64_t addr, int count) -> std::vector<uint8_t> {
        ghidra::Address gAddr = af->oldGetAddressFromLong(addr);
        std::vector<uint8_t> buf(count);
        try {
            int got = mem->getBytes(gAddr, buf.data(), count);
            buf.resize(got);
            return buf;
        } catch (...) {}
        return {};
    };

    auto isPrintableAscii = [](uint8_t b) -> bool {
        return (b >= 0x20 && b < 0x7F) || b == '\t' || b == '\n' || b == '\r';
    };

    for (auto* block : allBlocks) {
        if (!block) continue;
        if (!(block->getFlags() & ghidra::MemoryBlock::FLAG_EXECUTE)) continue;
        uint64_t blockStart = block->getStart().getUnsignedOffset();
        uint64_t blockEnd = blockStart + block->getSize();

        uint64_t gapStart = blockStart;
        for (uint64_t a = blockStart; a < blockEnd; ++a) {
            if (coveredAddresses.count(a)) {
                if (a > gapStart) {
                    uint64_t gapSize = a - gapStart;
                    if (gapSize >= 4) {
                        auto bytes = getBlockBytes(gapStart, static_cast<int>(gapSize));
                        if (bytes.size() >= 4) {
                            QString text = analyzeGap(program, gapStart, a);
                            if (!text.isEmpty()) {
                                DisasmRow row;
                                row.kind = DisasmRow::Kind::GapComment;
                                row.address = gapStart;
                                row.text = text;
                                gapRows.push_back(row);
                            }
                        }
                    }
                }
                gapStart = a + 1;
            }
        }
        if (gapStart < blockEnd) {
            uint64_t gapSize = blockEnd - gapStart;
            if (gapSize >= 4) {
                auto bytes = getBlockBytes(gapStart, static_cast<int>(gapSize));
                if (bytes.size() >= 4) {
                    QString text = analyzeGap(program, gapStart, blockEnd);
                    if (!text.isEmpty()) {
                        DisasmRow row;
                        row.kind = DisasmRow::Kind::GapComment;
                        row.address = gapStart;
                        row.text = text;
                        gapRows.push_back(row);
                    }
                }
            }
        }
    }

    // --- Merge all rows in address order ---
    std::vector<DisasmRow> dataRows;
    buildDataSections(program, dataRows);
    rows_ = std::move(instructionAndHeaderRows);
    rows_.insert(rows_.end(), gapRows.begin(), gapRows.end());
    rows_.insert(rows_.end(), dataRows.begin(), dataRows.end());
    std::stable_sort(rows_.begin(), rows_.end(),
        [](const DisasmRow& a, const DisasmRow& b) {
            if (a.address != b.address) return a.address < b.address;
            int pa = (a.kind == DisasmRow::Kind::FunctionHeader) ? 0 : 1;
            int pb = (b.kind == DisasmRow::Kind::FunctionHeader) ? 0 : 1;
            return pa < pb;
        });

    instrCount_ = 0;
    for (size_t i = 0; i < rows_.size(); ++i) {
        if (rows_[i].kind == DisasmRow::Kind::Instruction) {
            addressToRow_[rows_[i].address] = static_cast<int>(i);
            ++instrCount_;
        } else if (rows_[i].kind == DisasmRow::Kind::DataSection && rows_[i].length > 0) {
            // Map every byte of the chunk so addressToRow() resolves data addresses
            // (Hex → Disassembly sync lands precisely inside the byte dump).
            uint64_t end = rows_[i].address + static_cast<uint64_t>(rows_[i].length);
            for (uint64_t a = rows_[i].address; a < end; ++a)
                addressToRow_[a] = static_cast<int>(i);
        }
    }

    // --- Fill per-block info ---
    for (auto* block : allBlocks) {
        if (!block) continue;
        MemoryBlockInfo bi;
        bi.start = block->getStart().getUnsignedOffset();
        bi.size = block->getSize();
        bi.executable = (block->getFlags() & ghidra::MemoryBlock::FLAG_EXECUTE) != 0;
        bi.firstRow = -1;
        bi.instrCount = 0;
        for (size_t i = 0; i < rows_.size(); ++i) {
            const DisasmRow& r = rows_[i];
            if (r.address < bi.start) continue;
            if (r.address >= bi.start + bi.size) break;
            if (bi.firstRow < 0) bi.firstRow = static_cast<int>(i);
            if (r.kind == DisasmRow::Kind::Instruction) ++bi.instrCount;
        }
        blocks_.push_back(bi);
    }
}

const DisasmRow* DisassemblyModel::rowAt(int row) const {
    if (row < 0 || row >= static_cast<int>(rows_.size())) return nullptr;
    return &rows_[row];
}

uint64_t DisassemblyModel::rowToAddress(int row) const {
    const DisasmRow* r = rowAt(row);
    return r ? r->address : 0;
}

int DisassemblyModel::addressToRow(uint64_t addr) const {
    auto it = addressToRow_.find(addr);
    if (it != addressToRow_.end())
        return it->second;
    return -1;
}

int DisassemblyModel::instructionLengthAt(uint64_t addr) const {
    auto it = lengthByAddress_.find(addr);
    if (it != lengthByAddress_.end())
        return it->second;
    return 0;
}

void DisassemblyModel::buildDataSections(ghidra::ProgramDB* program,
                                         std::vector<DisasmRow>& outRows) {
    auto* mem = program->getMemory();
    auto* af = program->getAddressFactory();
    if (!mem || !af) return;

    auto allBlocks = mem->getBlocks();
    for (auto* block : allBlocks) {
        if (!block) continue;
        if (block->getFlags() & ghidra::MemoryBlock::FLAG_EXECUTE) continue; // handled by code/gap paths
        if (!block->isInitialized()) continue; // uninitialized (.bss) has no bytes to dump

        uint64_t blockStart = block->getStart().getUnsignedOffset();
        uint64_t blockSize = static_cast<uint64_t>(block->getSize());
        if (blockSize == 0) continue;

        DisasmRow header;
        header.kind = DisasmRow::Kind::DataSection;
        header.address = blockStart;
        header.length = 0;
        header.text = QString("; === %1 (0x%2 - 0x%3) ===")
            .arg(QString::fromStdString(block->getName()))
            .arg(blockStart, 0, 16)
            .arg(blockStart + blockSize, 0, 16);
        outRows.push_back(header);

        // Byte dump in 16-byte rows (same granularity as the HexView).
        constexpr uint64_t kChunk = 16;
        std::vector<uint8_t> buf(static_cast<size_t>(kChunk));
        for (uint64_t off = 0; off < blockSize; off += kChunk) {
            uint64_t n = (std::min)(kChunk, blockSize - off);
            uint64_t addr = blockStart + off;
            int got = 0;
            try {
                got = mem->getBytes(af->oldGetAddressFromLong(addr), buf.data(),
                                    static_cast<int>(n));
            } catch (...) { got = 0; }
            if (got <= 0) break;

            DisasmRow row;
            row.kind = DisasmRow::Kind::DataSection;
            row.address = addr;
            row.length = got;

            QString hexPart;
            QString asciiPart;
            for (int i = 0; i < got; ++i) {
                if (i) hexPart += QLatin1Char(' ');
                hexPart += QStringLiteral("%1").arg(buf[i], 2, 16, QLatin1Char('0'));
                uint8_t b = buf[i];
                asciiPart += (b >= 0x20 && b < 0x7F) ? QChar(static_cast<char>(b))
                                                     : QLatin1Char('.');
            }
            row.text = QString("0x%1  %2  %3")
                .arg(addr, 12, 16, QLatin1Char('0'))
                .arg(hexPart, -47, QLatin1Char(' '))
                .arg(asciiPart);
            outRows.push_back(std::move(row));
        }
    }
}

QString DisassemblyModel::analyzeGap(ghidra::ProgramDB* program, uint64_t gapStart, uint64_t gapEnd) const {
    auto* mem = program->getMemory();
    auto* af = program->getAddressFactory();
    if (!mem || !af) return QString();

    uint64_t gapSize = gapEnd - gapStart;
    if (gapSize < 4) return QString();

    ghidra::Address gAddr = af->oldGetAddressFromLong(gapStart);
    std::vector<uint8_t> bytes(static_cast<size_t>(gapSize));
    int got = 0;
    try {
        got = mem->getBytes(gAddr, bytes.data(), static_cast<int>(gapSize));
    } catch (...) { got = 0; }
    if (got < 4) return QString();
    bytes.resize(static_cast<size_t>(got));

    auto isPrintableAscii = [](uint8_t b) -> bool {
        return (b >= 0x20 && b < 0x7F) || b == '\t' || b == '\n' || b == '\r';
    };
    auto isInExecBlock = [&](uint64_t addr) -> bool {
        auto allBlocks = mem->getBlocks();
        for (auto* b : allBlocks) {
            if (!b) continue;
            if (!(b->getFlags() & ghidra::MemoryBlock::FLAG_EXECUTE)) continue;
            uint64_t bs = b->getStart().getUnsignedOffset();
            if (addr >= bs && addr < bs + b->getSize()) return true;
        }
        return false;
    };

    // Zero padding
    bool allZero = true;
    for (auto b : bytes) { if (b != 0) { allZero = false; break; } }
    if (allZero)
        return QString("; --- %1 bytes of zero padding ---").arg(gapSize);

    // ASCII string data
    int printableCount = 0;
    for (auto b : bytes)
        if (isPrintableAscii(b)) ++printableCount;
    double printableRatio = static_cast<double>(printableCount) / bytes.size();
    if (printableRatio > 0.85) {
        std::string str;
        for (auto b : bytes) {
            if (b == 0) break;
            if (isPrintableAscii(b)) str += static_cast<char>(b);
            else { str.clear(); break; }
        }
        if (str.size() >= 3)
            return QString("; --- string data: \"%1\" ---")
                .arg(QString::fromStdString(str).left(80));
    }

    // Pointer table (64-bit)
    if (gapSize >= 8 && (gapSize % 8) == 0) {
        int validPtrs = 0;
        for (size_t i = 0; i + 7 < bytes.size(); i += 8) {
            uint64_t val = 0;
            for (int j = 0; j < 8; ++j) val |= static_cast<uint64_t>(bytes[i + j]) << (j * 8);
            if (val >= 0x10000 && isInExecBlock(val)) ++validPtrs;
        }
        if (validPtrs >= 2) {
            QString result = QString("; --- pointer table (%1 entries) ---").arg(gapSize / 8);
            for (size_t i = 0; i + 7 < bytes.size(); i += 8) {
                uint64_t val = 0;
                for (int j = 0; j < 8; ++j) val |= static_cast<uint64_t>(bytes[i + j]) << (j * 8);
                result += QString("\n;   0x%1 -> 0x%2")
                    .arg(gapStart + i, 0, 16)
                    .arg(val, 0, 16);
            }
            return result;
        }
    }

    // Pointer table (32-bit)
    if (gapSize >= 4 && (gapSize % 4) == 0) {
        int validPtrs = 0;
        for (size_t i = 0; i + 3 < bytes.size(); i += 4) {
            uint32_t val = 0;
            for (int j = 0; j < 4; ++j) val |= static_cast<uint32_t>(bytes[i + j]) << (j * 8);
            if (val >= 0x10000 && isInExecBlock(val)) ++validPtrs;
        }
        if (validPtrs >= 2) {
            QString result = QString("; --- pointer table (%1 entries) ---").arg(gapSize / 4);
            for (size_t i = 0; i + 3 < bytes.size(); i += 4) {
                uint32_t val = 0;
                for (int j = 0; j < 4; ++j) val |= static_cast<uint32_t>(bytes[i + j]) << (j * 8);
                result += QString("\n;   0x%1 -> 0x%2")
                    .arg(gapStart + i, 0, 16)
                    .arg(val, 0, 16);
            }
            return result;
        }
    }

    // Generic hex dump
    QString hexdump;
    int showBytes = static_cast<int>((std::min)(gapSize, static_cast<uint64_t>(32)));
    for (int i = 0; i < showBytes; ++i)
        hexdump += QString("%1 ").arg(bytes[i], 2, 16, QLatin1Char('0'));
    if (gapSize > 32) hexdump += "...";
    return QString("; --- %1 bytes of data: %2 ---").arg(gapSize).arg(hexdump.trimmed());
}
