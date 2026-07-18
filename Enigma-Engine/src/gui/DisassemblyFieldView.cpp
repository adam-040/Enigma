#include "DisassemblyFieldView.h"
#include <ghidra/ProgramDB.h>
#include <ghidra/DecompInterface.h>
#include <ghidra/Memory.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/FunctionIterator.h>
#include <ghidra/Function.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SymbolIterator.h>
#include <ghidra/Symbol.h>
#include <ghidra/SymbolType.h>
#include <iostream>
#include <algorithm>
#include <set>
#include <ghidra/Address.h>
#include <ghidra/AddressFactory.h>
#include <QMenu>

DisassemblyFieldView::DisassemblyFieldView(QWidget* parent)
    : FieldView(parent)
{
}

void DisassemblyFieldView::setProgram(ghidra::ProgramDB* program) {
    program_ = program;
    indexBuilt_ = false;
}

void DisassemblyFieldView::setDecompInterface(ghidra::DecompInterface* decomp) {
    decomp_ = decomp;
    indexBuilt_ = false;
}

void DisassemblyFieldView::setShowBytes(bool show) {
    showBytes_ = show;
    if (parsed_.empty() && !lastText_.isEmpty()) {
        showDisassembly(lastText_);
    } else if (!parsed_.empty()) {
        uint64_t currentAddr = addressAtCurrentLine();
        buildDocumentFromParsed();
        if (currentAddr != 0)
            seek(currentAddr);
    }
}

bool DisassemblyFieldView::showBytes() const {
    return showBytes_;
}

void DisassemblyFieldView::buildFullIndex() {
    std::cerr << "[buildFullIndex] ENTER program_=" << (void*)program_ << " decomp_=" << (void*)decomp_ << std::endl;
    if (!program_ || !decomp_ || !decomp_->isOpen()) {
        std::cerr << "[buildFullIndex] ABORT: program_=" << (void*)program_ << " decomp_=" << (void*)decomp_
                  << " isOpen=" << (decomp_ ? decomp_->isOpen() : false) << std::endl;
        return;
    }

    auto* mem = program_->getMemory();
    auto* af = program_->getAddressFactory();
    auto* fm = program_->getFunctionManager();
    auto* st = program_->getSymbolTable();
    if (!mem || !af) {
        std::cerr << "[buildFullIndex] ABORT: mem=" << (void*)mem << " af=" << (void*)af << std::endl;
        return;
    }

    auto allBlocks = mem->getBlocks();
    std::cerr << "[buildFullIndex] blocks count=" << allBlocks.size() << std::endl;
    if (allBlocks.empty()) return;

    // --- Collect known functions from FunctionManager ---
    struct FuncInfo {
        uint64_t entry;
        uint64_t bodyStart;
        uint64_t bodyEnd;
        std::string name;
        bool thunk;
    };
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
            functions.push_back({ entry, bStart, bEnd, func->getName(), func->isThunk() });
            for (uint64_t a = bStart; a <= bEnd; ++a)
                coveredAddresses.insert(a);
        }
    }
    std::cerr << "[buildFullIndex] known functions: " << functions.size() << std::endl;

    // --- IMPROVEMENT 1: Add exports/symbols not yet covered ---
    auto isInExecBlock = [&](uint64_t addr) -> bool {
        for (auto* b : allBlocks) {
            if (!b) continue;
            if (!(b->getFlags() & ghidra::MemoryBlock::FLAG_EXECUTE)) continue;
            uint64_t bs = b->getStart().getUnsignedOffset();
            if (addr >= bs && addr < bs + b->getSize()) return true;
        }
        return false;
    };

    int symbolAdditions = 0;
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
            // Not covered — add as a discovered function
            std::string name = sym->getName();
            if (name.empty()) {
                std::ostringstream oss;
                oss << "sub_0x" << std::hex << addr;
                name = oss.str();
            }
            functions.push_back({ addr, addr, addr + 0xFF, name, false });
            for (uint64_t a = addr; a <= addr + 0xFF; ++a)
                coveredAddresses.insert(a);
            ++symbolAdditions;
        }
    }
    std::cerr << "[buildFullIndex] added " << symbolAdditions << " symbol-based functions" << std::endl;

    // Sort by body start
    std::sort(functions.begin(), functions.end(),
        [](const FuncInfo& a, const FuncInfo& b) { return a.bodyStart < b.bodyStart; });

    // --- Disassemble function-by-function ---
    // Use a queue for flow-following: new addresses discovered from CALL targets go here
    std::vector<FuncInfo> toDisassemble = functions;
    std::set<uint64_t> seenEntries;
    for (auto& f : toDisassemble) seenEntries.insert(f.entry);

    // Helper to extract CALL/JMP target addresses from disassembly text
    // Format: "0xADDR:  MNEM  TARGET" — e.g. "0x140001234:  CALL  0x140005678"
    auto extractCallTargets = [&](const QString& text) -> std::vector<uint64_t> {
        std::vector<uint64_t> targets;
        for (const auto& line : text.split(QLatin1Char('\n'))) {
            // Find "CALL 0x" or "JMP 0x" anywhere in the line
            int callIdx = line.indexOf("CALL 0x");
            if (callIdx < 0) callIdx = line.indexOf("CALL\t0x");
            if (callIdx >= 0) {
                QString rest = line.mid(callIdx + 4).trimmed();
                bool ok;
                uint64_t addr = rest.toULongLong(&ok, 16);
                if (ok && addr != 0) targets.push_back(addr);
            }
            int jmpIdx = line.indexOf("JMP 0x");
            if (jmpIdx < 0) jmpIdx = line.indexOf("JMP\t0x");
            if (jmpIdx >= 0) {
                QString rest = line.mid(jmpIdx + 3).trimmed();
                bool ok;
                uint64_t addr = rest.toULongLong(&ok, 16);
                if (ok && addr != 0) targets.push_back(addr);
            }
        }
        return targets;
    };

    QString allText;
    int round = 0;
    int flowDiscoveries = 0;

    while (!toDisassemble.empty()) {
        ++round;
        std::vector<FuncInfo> currentBatch = std::move(toDisassemble);
        toDisassemble.clear();
        std::cerr << "[buildFullIndex] round " << round << " disassembling " << currentBatch.size() << " functions" << std::endl;

        // Sort this batch by entry for clean output
        std::sort(currentBatch.begin(), currentBatch.end(),
            [](const FuncInfo& a, const FuncInfo& b) { return a.entry < b.entry; });

        for (auto& func : currentBatch) {
            if (seenEntries.count(func.entry) && round > 1) {
                // Already disassembled in a previous round
                // But we still need to emit it if it wasn't emitted before
                // Check if it was already in the text
                QString entryHex = QString("0x%1").arg(func.entry, 0, 16);
                if (allText.contains(entryHex)) continue;
            }
            seenEntries.insert(func.entry);

            uint64_t disasmEnd = func.bodyEnd;
            if (disasmEnd >= func.entry + 0x1000) disasmEnd = func.entry + 0x1000; // cap at 4KB
            int maxBytes = static_cast<int>(disasmEnd - func.entry + 1);
            if (maxBytes <= 0 || maxBytes > 0x10000) maxBytes = 0x1000;

            ghidra::Address funcAddr = af->oldGetAddressFromLong(func.entry);
            try {
                std::string text = decomp_->disassembleAt(funcAddr, 10000, maxBytes);
                if (!text.empty()) {
                    QString qtext = QString::fromStdString(text);
                    allText += QString("\n; === %1 ===\n").arg(QString::fromStdString(func.name));
                    allText += qtext;

                    // --- IMPROVEMENT 2: Flow-following — extract CALL targets ---
                    if (round <= 2) {
                        auto targets = extractCallTargets(qtext);
                        for (uint64_t tgt : targets) {
                            if (tgt == 0 || seenEntries.count(tgt)) continue;
                            if (!isInExecBlock(tgt)) continue;
                            if (coveredAddresses.count(tgt)) continue;
                            // Found a new function via flow
                            std::ostringstream oss;
                            oss << "sub_0x" << std::hex << tgt;
                            toDisassemble.push_back({ tgt, tgt, tgt + 0xFF, oss.str(), false });
                            for (uint64_t a = tgt; a <= tgt + 0xFF; ++a)
                                coveredAddresses.insert(a);
                            ++flowDiscoveries;
                        }
                    }
                }
            } catch (const std::exception& e) {
                allText += QString("; disassembly failed for %1: %2\n")
                    .arg(QString::fromStdString(func.name)).arg(e.what());
            } catch (...) {
                allText += QString("; disassembly failed for %1 (unknown)\n")
                    .arg(QString::fromStdString(func.name));
            }
        }
    }
    std::cerr << "[buildFullIndex] flow-following discovered " << flowDiscoveries << " new functions" << std::endl;

    // --- IMPROVEMENT 3: Analyze uncovered data gaps ---
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

    auto analyzeDataGap = [&](uint64_t gapStart, uint64_t gapEnd) -> QString {
        uint64_t gapSize = gapEnd - gapStart;
        if (gapSize < 4) return QString();

        auto bytes = getBlockBytes(gapStart, static_cast<int>(gapSize));
        if (bytes.size() < 4) return QString();

        // Check for zero padding (alignment)
        bool allZero = true;
        for (auto b : bytes) { if (b != 0) { allZero = false; break; } }
        if (allZero) {
            return QString("; --- %1 bytes of zero padding ---\n").arg(gapSize);
        }

        // Check for ASCII string data
        int printableCount = 0;
        int nullTerminated = 0;
        for (auto b : bytes) {
            if (isPrintableAscii(b)) ++printableCount;
            if (b == 0) ++nullTerminated;
        }
        double printableRatio = static_cast<double>(printableCount) / bytes.size();
        if (printableRatio > 0.85 && gapSize >= 4) {
            // Try to read as null-terminated string
            std::string str;
            for (auto b : bytes) {
                if (b == 0) break;
                if (isPrintableAscii(b)) str += static_cast<char>(b);
                else { str.clear(); break; }
            }
            if (str.size() >= 3) {
                return QString("; --- string data: \"%1\" ---\n")
                    .arg(QString::fromStdString(str).left(80));
            }
        }

        // Check for pointer table (array of 8-byte or 4-byte values pointing to valid addresses)
        bool looksLikePtrTable64 = false;
        bool looksLikePtrTable32 = false;
        if (gapSize >= 8 && (gapSize % 8) == 0) {
            int validPtrs = 0;
            for (size_t i = 0; i + 7 < bytes.size(); i += 8) {
                uint64_t val = 0;
                for (int j = 0; j < 8; ++j) val |= static_cast<uint64_t>(bytes[i + j]) << (j * 8);
                if (val >= 0x10000 && isInExecBlock(val)) ++validPtrs;
            }
            if (validPtrs >= 2) looksLikePtrTable64 = true;
        }
        if (gapSize >= 4 && (gapSize % 4) == 0 && !looksLikePtrTable64) {
            int validPtrs = 0;
            for (size_t i = 0; i + 3 < bytes.size(); i += 4) {
                uint32_t val = 0;
                for (int j = 0; j < 4; ++j) val |= static_cast<uint32_t>(bytes[i + j]) << (j * 8);
                if (val >= 0x10000 && isInExecBlock(val)) ++validPtrs;
            }
            if (validPtrs >= 2) looksLikePtrTable32 = true;
        }

        if (looksLikePtrTable64) {
            QString result = QString("; --- pointer table (%1 entries) ---\n").arg(gapSize / 8);
            for (size_t i = 0; i + 7 < bytes.size(); i += 8) {
                uint64_t val = 0;
                for (int j = 0; j < 8; ++j) val |= static_cast<uint64_t>(bytes[i + j]) << (j * 8);
                result += QString(";   0x%1 -> 0x%2\n")
                    .arg(gapStart + i, 0, 16)
                    .arg(val, 0, 16);
            }
            return result;
        }
        if (looksLikePtrTable32) {
            QString result = QString("; --- pointer table (%1 entries) ---\n").arg(gapSize / 4);
            for (size_t i = 0; i + 3 < bytes.size(); i += 4) {
                uint32_t val = 0;
                for (int j = 0; j < 4; ++j) val |= static_cast<uint32_t>(bytes[i + j]) << (j * 8);
                result += QString(";   0x%1 -> 0x%2\n")
                    .arg(gapStart + i, 0, 16)
                    .arg(val, 0, 16);
            }
            return result;
        }

        // Generic data — show first 16 bytes as hex dump
        QString hexdump;
        int showBytes = static_cast<int>((std::min)(gapSize, static_cast<uint64_t>(32)));
        for (int i = 0; i < showBytes; ++i)
            hexdump += QString("%1 ").arg(bytes[i], 2, 16, QLatin1Char('0'));
        if (gapSize > 32) hexdump += "...";
        return QString("; --- %1 bytes of data: %2 ---\n").arg(gapSize).arg(hexdump.trimmed());
    };

    for (auto* block : allBlocks) {
        if (!block) continue;
        if (!(block->getFlags() & ghidra::MemoryBlock::FLAG_EXECUTE)) continue;
        uint64_t blockStart = block->getStart().getUnsignedOffset();
        uint64_t blockEnd = blockStart + block->getSize();

        // Find uncovered ranges within this block
        uint64_t gapStart = blockStart;
        for (uint64_t a = blockStart; a < blockEnd; ++a) {
            if (coveredAddresses.count(a)) {
                if (a > gapStart) {
                    allText += analyzeDataGap(gapStart, a);
                }
                gapStart = a + 1;
            }
        }
        if (gapStart < blockEnd) {
            allText += analyzeDataGap(gapStart, blockEnd);
        }
    }

    std::cerr << "[buildFullIndex] allText.size=" << allText.size() << std::endl;
    if (allText.isEmpty())
        return;

    indexBuilt_ = true;
    lastText_ = allText;
    showDisassembly(allText);
    std::cerr << "[buildFullIndex] DONE indexBuilt_=true" << std::endl;
}

void DisassemblyFieldView::seekToAddress(uint64_t addr) {
    if (!indexBuilt_ || !document())
        return;

    seek(addr);
}

void DisassemblyFieldView::contextMenuEvent(QContextMenuEvent* event) {
    auto hit = caretAtPos(event->pos());
    if (hit.line < 0 || hit.col < 0 || !document()) {
        FieldView::contextMenuEvent(event);
        return;
    }

    const Token* tok = tokenAt(hit.line, hit.col);
    if (!tok || tok->addr == 0) {
        FieldView::contextMenuEvent(event);
        return;
    }

    uint64_t addr = tok->addr;
    QMenu menu(this);

    QAction* actAssemble = menu.addAction(tr("Assemble Instruction at 0x%1").arg(addr, 0, 16));
    menu.addSeparator();
    QAction* actGoTo = menu.addAction(tr("Go to 0x%1").arg(addr, 0, 16));

    QAction* actJumpToCave = nullptr;
    auto caveIt = trampolineMap_.find(addr);
    if (caveIt != trampolineMap_.end()) {
        actJumpToCave = menu.addAction(tr("Jump to Code Cave (0x%1)").arg(caveIt->second, 0, 16));
    }

    QAction* chosen = menu.exec(event->globalPos());
    if (!chosen) return;

    if (chosen == actAssemble) {
        QString currentMnemonic;
        QString currentOperands;
        if (hit.line >= 0 && hit.line < static_cast<int>(parsed_.size())) {
            currentMnemonic = parsed_[hit.line].mne;
            currentOperands = parsed_[hit.line].body;
        }
        emit patchInstructionRequested(addr, currentMnemonic, currentOperands);
    } else if (actJumpToCave && chosen == actJumpToCave) {
        emit addressJumpRequested(caveIt->second);
    } else if (chosen == actGoTo) {
        seek(addr);
    }
}

static bool isCommentLine(const QString& trimmed) {
    return trimmed.startsWith(QLatin1Char(';'))
        || trimmed.startsWith(QStringLiteral("//"));
}

static std::vector<uint8_t> fetchBytesLocal(ghidra::ProgramDB* program, uint64_t addr, int len) {
    if (!program || len <= 0) return {};
    auto* mem = program->getMemory();
    auto* af = program->getAddressFactory();
    if (!mem || !af) return {};
    ghidra::Address a = af->oldGetAddressFromLong(addr);
    std::vector<uint8_t> buf(len);
    try {
        int got = mem->getBytes(a, buf.data(), len);
        if (got > 0) {
            buf.resize(got);
            return buf;
        }
    } catch (...) {}
    return {};
}

void DisassemblyFieldView::showDisassembly(const QString& text) {
    std::cerr << "[showDisassembly] text.size=" << text.size() << " first80='" << text.left(80).toStdString() << "'" << std::endl;
    lastText_ = text;
    parsed_.clear();

    QString expanded = text;
    expanded.replace(QLatin1Char('\t'), QString(8, QLatin1Char(' ')));
    QStringList rawLines = expanded.split(QLatin1Char('\n'));

    parsed_.reserve(rawLines.size());

    static QRegularExpression instRe(
        QStringLiteral("^0x([0-9a-fA-F]+):\\s+([A-Za-z][A-Za-z0-9]*)\\s*(.*)$"));

    for (const QString& rawLine : rawLines) {
        if (rawLine.trimmed().isEmpty()) {
            parsed_.push_back(ParsedLine{});
            continue;
        }
        QString trimmed = rawLine.trimmed();
        if (isCommentLine(trimmed)) {
            ParsedLine rl;
            rl.body = trimmed;
            parsed_.push_back(rl);
            continue;
        }
        auto m = instRe.match(trimmed);
        if (m.hasMatch()) {
            ParsedLine rl;
            bool ok = false;
            rl.addr = m.captured(1).toULongLong(&ok, 16);
            rl.mne = m.captured(2);
            rl.body = m.captured(3);
            parsed_.push_back(rl);
        } else {
            ParsedLine rl;
            rl.body = trimmed;
            parsed_.push_back(rl);
        }
    }

    buildDocumentFromParsed();
}

void DisassemblyFieldView::buildDocumentFromParsed() {
    auto doc = std::make_unique<Document>();

    for (size_t i = 0; i < parsed_.size(); ++i) {
        const ParsedLine& rl = parsed_[i];
        if (rl.body.isEmpty() && rl.mne.isEmpty()) {
            doc->addLine(Line{});
            continue;
        }

        Line l;
        l.addr = rl.addr;

        if (!rl.mne.isEmpty()) {
            Token addrTok;
            addrTok.text = QStringLiteral("0x%1  ").arg(rl.addr, 8, 16, QLatin1Char('0'));
            addrTok.kind = TokenKind::Address;
            addrTok.addr = rl.addr;
            l.tokens.push_back(addrTok);

            int len = 0;
            try {
                if (i + 1 < parsed_.size() && parsed_[i + 1].addr > rl.addr)
                    len = static_cast<int>(parsed_[i + 1].addr - rl.addr);
                else if (decomp_)
                    len = decomp_->instructionLengthAt(rl.addr);
            } catch (...) {
                len = 0;
            }

            if (showBytes_ && len > 0) {
                try {
                    l.bytes = fetchBytesLocal(program_, rl.addr, len);
                } catch (...) {
                    l.bytes = {};
                }
                if (!l.bytes.empty()) {
                    Token bytesTok;
                    bytesTok.text = formatBytes(l.bytes);
                    bytesTok.kind = TokenKind::Bytes;
                    bytesTok.addr = rl.addr;
                    int gap = 30 - static_cast<int>(bytesTok.text.size());
                    bytesTok.spaceAfter = (gap >= 2) ? gap : 2;
                    l.tokens.push_back(bytesTok);
                }
            }

            Token mneTok;
            mneTok.text = rl.mne.leftJustified(8, QLatin1Char(' '));
            mneTok.kind = isBranchMnemonic(rl.mne) ? TokenKind::Branch : TokenKind::Mnemonic;
            mneTok.addr = rl.addr;
            l.tokens.push_back(mneTok);

            auto opTokens = tokenizeOperands(rl.body, rl.addr);
            for (auto& t : opTokens)
                l.tokens.push_back(t);

        } else {
            Token t;
            t.text = rl.body;
            t.kind = isCommentLine(rl.body) ? TokenKind::Comment : TokenKind::Plain;
            l.tokens.push_back(t);
        }

        doc->addLine(l);
    }

    doc->finalize();
    setDocument(std::move(doc));
}

QString DisassemblyFieldView::formatBytes(const std::vector<uint8_t>& bytes) {
    QString out;
    for (size_t i = 0; i < bytes.size(); ++i) {
        if (i) out += QLatin1Char(' ');
        out += QStringLiteral("%1").arg(bytes[i], 2, 16, QLatin1Char('0'));
    }
    return out;
}

bool DisassemblyFieldView::isBranchMnemonic(const QString& mne) {
    static const QStringList branch = {
        QStringLiteral("CALL"), QStringLiteral("JMP"), QStringLiteral("JMPF"),
        QStringLiteral("JE"), QStringLiteral("JNE"), QStringLiteral("JZ"), QStringLiteral("JNZ"),
        QStringLiteral("JA"), QStringLiteral("JAE"), QStringLiteral("JB"), QStringLiteral("JBE"),
        QStringLiteral("JG"), QStringLiteral("JGE"), QStringLiteral("JL"), QStringLiteral("JLE"),
        QStringLiteral("JO"), QStringLiteral("JNO"), QStringLiteral("JS"), QStringLiteral("JNS"),
        QStringLiteral("JP"), QStringLiteral("JNP"), QStringLiteral("JC"), QStringLiteral("JNC"),
        QStringLiteral("RET"), QStringLiteral("RETN"), QStringLiteral("RETF"),
        QStringLiteral("IRET"), QStringLiteral("IRETD"), QStringLiteral("IRETQ"),
        QStringLiteral("SYSCALL"), QStringLiteral("SYSRET"), QStringLiteral("SYSENTER"),
        QStringLiteral("INT"), QStringLiteral("INT3"), QStringLiteral("INTO"),
        QStringLiteral("LOOP"), QStringLiteral("LOOPE"), QStringLiteral("LOOPNE"),
        QStringLiteral("LOOPZ"), QStringLiteral("LOOPNZ")
    };
    return branch.contains(mne.toUpper());
}

TokenKind DisassemblyFieldView::classifyIdentifier(const QString& id) const {
    static const QStringList registers = {
        QStringLiteral("eax"), QStringLiteral("ebx"), QStringLiteral("ecx"),
        QStringLiteral("edx"), QStringLiteral("esi"), QStringLiteral("edi"),
        QStringLiteral("ebp"), QStringLiteral("esp"), QStringLiteral("eip"),
        QStringLiteral("rax"), QStringLiteral("rbx"), QStringLiteral("rcx"),
        QStringLiteral("rdx"), QStringLiteral("rsi"), QStringLiteral("rdi"),
        QStringLiteral("rbp"), QStringLiteral("rsp"), QStringLiteral("rip"),
        QStringLiteral("r8"),  QStringLiteral("r9"),  QStringLiteral("r10"),
        QStringLiteral("r11"), QStringLiteral("r12"), QStringLiteral("r13"),
        QStringLiteral("r14"), QStringLiteral("r15"),
        QStringLiteral("r8d"), QStringLiteral("r9d"), QStringLiteral("r10d"),
        QStringLiteral("r11d"),QStringLiteral("r12d"),QStringLiteral("r13d"),
        QStringLiteral("r14d"),QStringLiteral("r15d"),
        QStringLiteral("r8w"), QStringLiteral("r9w"), QStringLiteral("r10w"),
        QStringLiteral("r11w"),QStringLiteral("r12w"),QStringLiteral("r13w"),
        QStringLiteral("r14w"),QStringLiteral("r15w"),
        QStringLiteral("r8b"), QStringLiteral("r9b"), QStringLiteral("r10b"),
        QStringLiteral("r11b"),QStringLiteral("r12b"),QStringLiteral("r13b"),
        QStringLiteral("r14b"),QStringLiteral("r15b"),
        QStringLiteral("ax"),  QStringLiteral("bx"),  QStringLiteral("cx"),
        QStringLiteral("dx"),  QStringLiteral("si"),  QStringLiteral("di"),
        QStringLiteral("bp"),  QStringLiteral("sp"),
        QStringLiteral("ah"),  QStringLiteral("bh"),  QStringLiteral("ch"),
        QStringLiteral("dh"),  QStringLiteral("al"),  QStringLiteral("bl"),
        QStringLiteral("cl"),  QStringLiteral("dl"),
        QStringLiteral("sil"), QStringLiteral("dil"), QStringLiteral("bpl"),
        QStringLiteral("spl"),
        QStringLiteral("xmm0"), QStringLiteral("xmm1"), QStringLiteral("xmm2"),
        QStringLiteral("xmm3"), QStringLiteral("xmm4"), QStringLiteral("xmm5"),
        QStringLiteral("xmm6"), QStringLiteral("xmm7"),
        QStringLiteral("ymm0"), QStringLiteral("ymm1"), QStringLiteral("ymm2"),
        QStringLiteral("ymm3"), QStringLiteral("ymm4"), QStringLiteral("ymm5"),
        QStringLiteral("ymm6"), QStringLiteral("ymm7"),
        QStringLiteral("cs"),  QStringLiteral("ds"),  QStringLiteral("es"),
        QStringLiteral("fs"),  QStringLiteral("gs"),  QStringLiteral("ss"),
        QStringLiteral("st0"), QStringLiteral("st1"), QStringLiteral("st2"),
        QStringLiteral("st3"), QStringLiteral("st4"), QStringLiteral("st5"),
        QStringLiteral("st6"), QStringLiteral("st7"),
    };
    QString lower = id.toLower();
    if (registers.contains(lower))
        return TokenKind::Register;
    bool allDigits = true;
    for (const QChar& c : id) {
        if (!c.isDigit()) { allDigits = false; break; }
    }
    if (allDigits) return TokenKind::Number;
    return TokenKind::Plain;
}

std::vector<Token> DisassemblyFieldView::tokenizeOperands(const QString& ops, uint64_t lineAddr) {
    std::vector<Token> result;
    int n = ops.size();
    int i = 0;
    int bracketDepth = 0;

    auto consumeSpaces = [&](int pos) {
        while (pos < n && ops[pos].isSpace()) ++pos;
        return pos;
    };

    auto addToken = [&](const QString& text, TokenKind kind) {
        if (text.isEmpty()) return;
        Token t;
        t.text = text;
        t.kind = kind;
        t.addr = lineAddr;
        result.push_back(t);
    };

    while (i < n) {
        QChar c = ops[i];
        if (c.isSpace()) {
            ++i;
            continue;
        }

        if (c == QLatin1Char('0') && i + 1 < n && ops[i + 1] == QLatin1Char('x')) {
            int j = i + 2;
            while (j < n && (ops[j].isDigit() ||
                             (ops[j] >= QLatin1Char('a') && ops[j] <= QLatin1Char('f')) ||
                             (ops[j] >= QLatin1Char('A') && ops[j] <= QLatin1Char('F')))) ++j;
            QString txt = ops.mid(i, j - i);
            Token t;
            t.text = txt;
            t.kind = bracketDepth > 0 ? TokenKind::MemRef : TokenKind::Immediate;
            t.addr = lineAddr;
            bool ok = false;
            uint64_t val = txt.mid(2).toULongLong(&ok, 16);
            if (ok && val > 0x1000) t.refTarget = val;
            result.push_back(t);
            i = consumeSpaces(j);
            result.back().spaceAfter = i - j;
            continue;
        }

        if (c.isLetter() || c == QLatin1Char('_')) {
            int j = i;
            while (j < n && (ops[j].isLetterOrNumber() || ops[j] == QLatin1Char('_'))) ++j;
            QString id = ops.mid(i, j - i);
            TokenKind k = classifyIdentifier(id);
            if (bracketDepth > 0 && k != TokenKind::Register) k = TokenKind::MemRef;
            addToken(id, k);
            i = consumeSpaces(j);
            result.back().spaceAfter = i - j;
            continue;
        }

        if (c == QLatin1Char('[')) {
            addToken(QStringLiteral("["), TokenKind::MemRef);
            ++bracketDepth;
            ++i;
            continue;
        }
        if (c == QLatin1Char(']')) {
            addToken(QStringLiteral("]"), TokenKind::MemRef);
            if (bracketDepth > 0) --bracketDepth;
            ++i;
            continue;
        }

        if (c == QLatin1Char('+') || c == QLatin1Char('-') || c == QLatin1Char('*') ||
            c == QLatin1Char(',') || c == QLatin1Char(':') ||
            c == QLatin1Char('(') || c == QLatin1Char(')')) {
            addToken(ops.mid(i, 1), bracketDepth > 0 ? TokenKind::MemRef : TokenKind::Punctuation);
            ++i;
            continue;
        }

        addToken(ops.mid(i, 1), bracketDepth > 0 ? TokenKind::MemRef : TokenKind::Plain);
        ++i;
    }
    return result;
}
