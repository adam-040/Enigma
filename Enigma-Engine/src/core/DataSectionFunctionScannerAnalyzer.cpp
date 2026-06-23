#include <ghidra/DataSectionFunctionScannerAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/AddressSet.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/SourceType.h>
#include <ghidra/Msg.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <unordered_set>
#include <vector>

namespace ghidra {

DataSectionFunctionScannerAnalyzer::DataSectionFunctionScannerAnalyzer()
    : AbstractAnalyzer("Data Section Function Scanner",
                       "Scans data sections for pointer values that reference code, "
                       "detecting functions reachable only via vtables, CRT init arrays, "
                       "and other data-referenced code.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::REFERENCE_ANALYSIS.after());
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

bool DataSectionFunctionScannerAnalyzer::canAnalyze(Program* program) const {
    return program != nullptr;
}

// Cache of (start,end) of every executable block for O(log N) "is in executable region" checks.
struct ExecBlockRange {
    uint64_t start;
    uint64_t end;
};

static const ExecBlockRange* findExecBlock(const std::vector<ExecBlockRange>& execBlocks,
                                             uint64_t addr) {
    // Binary search by start offset
    size_t lo = 0, hi = execBlocks.size();
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (execBlocks[mid].start <= addr && addr <= execBlocks[mid].end) {
            return &execBlocks[mid];
        } else if (addr < execBlocks[mid].start) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    return nullptr;
}

// PHASE 4: batch candidate collection. Scan data sections, collect pointer values
// (without per-candidate expensive checks), then validate in one pass.
static std::vector<uint64_t> collect8BytePointers(Memory* memory, TaskMonitor* monitor) {
    static constexpr int MAX_SCAN = 100000;
    std::vector<uint64_t> candidates;
    candidates.reserve(2048);

    int scanned = 0;
    for (auto* block : memory->getBlocks()) {
        if (monitor->isCancelled()) break;
        if (!block->isRead() || block->isExecute() || !block->isInitialized()) continue;

        std::string name = block->getName();
        if (name.rfind(".text") == 0 || name.rfind("text") == 0 ||
            name.rfind("CODE") == 0 || name.rfind(".glue") == 0 ||
            name.rfind(".rdata") == 0 || name.rfind("rdata") == 0) {
            continue;
        }

        Address start = block->getStart();
        Address end = block->getEnd();
        if (!start.isValid() || !end.isValid()) continue;

        uint64_t size = (end.getOffset() - start.getOffset() + 1);
        if (size > 16 * 1024 * 1024) size = 16 * 1024 * 1024;
        if (size < 8) continue;

        std::vector<uint8_t> buf(static_cast<size_t>(size));
        int read = block->getBytes(start, buf.data(), static_cast<int>(buf.size()));
        if (read < 8) continue;
        size = static_cast<uint64_t>(read);

        for (uint64_t off = 0; off <= size - 8 && scanned < MAX_SCAN;
             off += 8, ++scanned) {
            if (monitor->isCancelled()) break;

            uint64_t val = *reinterpret_cast<const uint64_t*>(buf.data() + off);
            if (val == 0 || val == UINT64_MAX) continue;
            if ((val & 1) != 0) continue;
            candidates.push_back(val);
        }
    }
    return candidates;
}

static std::vector<uint64_t> collect4ByteRVAs(Memory* memory, TaskMonitor* monitor,
                                                uint64_t imageBase) {
    static constexpr int MAX_SCAN = 100000;
    std::vector<uint64_t> candidates;
    candidates.reserve(2048);

    int scanned = 0;
    for (auto* block : memory->getBlocks()) {
        if (monitor->isCancelled()) break;
        if (!block->isRead() || block->isExecute() || !block->isInitialized()) continue;

        std::string name = block->getName();
        if (name.rfind(".text") == 0 || name.rfind("text") == 0 ||
            name.rfind("CODE") == 0 || name.rfind(".glue") == 0) {
            continue;
        }

        Address start = block->getStart();
        Address end = block->getEnd();
        if (!start.isValid() || !end.isValid()) continue;

        uint64_t size = (end.getOffset() - start.getOffset() + 1);
        if (size > 16 * 1024 * 1024) size = 16 * 1024 * 1024;
        if (size < 4) continue;

        std::vector<uint8_t> buf(static_cast<size_t>(size));
        int read = block->getBytes(start, buf.data(), static_cast<int>(buf.size()));
        if (read < 4) continue;
        size = static_cast<uint64_t>(read);

        for (uint64_t off = 0; off <= size - 4 && scanned < MAX_SCAN;
             off += 4, ++scanned) {
            if (monitor->isCancelled()) break;

            uint32_t rva = *reinterpret_cast<const uint32_t*>(buf.data() + off);
            if (rva == 0) continue;
            uint64_t absAddr = imageBase + rva;
            if (absAddr < imageBase) continue;
            candidates.push_back(absAddr);
        }
    }
    return candidates;
}

// Check if the given address looks like a plausible function boundary.
// The byte before the candidate should be CC (int3 padding), C3 (ret),
// or E9/EB (jmp tail call). These are unambiguous function boundaries.
// 0x90 (nop) and 0x00 (zero) are NOT reliable — they appear mid-function
// in alignment padding and instruction immediates.
//
// When is64Bit is true, also rejects addresses where the previous byte
// is an x86-64 instruction prefix (REX 0x40-0x4F, VEX 0xC5, segment
// overrides, LOCK 0xF0). These can ONLY appear immediately before the
// opcode byte, so the candidate would be a ModRM/displacement/immediate
// byte (mid-instruction), not a valid function start.
static bool isAtFunctionBoundary(Memory* memory, const Address& addr, bool is64Bit = false) {
    MemoryBlock* targetBlock = memory->getBlock(addr);
    if (!targetBlock) return false;
    if (addr == targetBlock->getStart()) return true;

    Address prev = addr.subtract(1);
    if (!prev.isValid()) return true;

    MemoryBlock* prevBlock = memory->getBlock(prev);
    if (prevBlock != targetBlock) return true;

    uint8_t prevByte = 0;
    try {
        int got = memory->getBytes(prev, &prevByte, 1);
        if (got < 1) return false;
    } catch (...) {
        return false;
    }

    if (is64Bit) {
        // In x86-64 mode, 0x40-0x4F are REX prefixes (never standalone opcodes).
        // If the preceding byte is a REX prefix, the candidate is the ModRM /
        // displacement / immediate byte (mid-instruction), not a function start.
        if (prevByte >= 0x40 && prevByte <= 0x4F) return false;

        // 2-byte VEX prefix (0xC5 + 1-byte payload → addr is opcode/ModRM)
        if (prevByte == 0xC5) return false;

        // 3-byte VEX prefix (0xC4 + 2-byte payload → addr is opcode/ModRM)
        if (prevByte == 0xC4) return false;

        // Segment overrides and LOCK prefix — only valid before the opcode byte.
        if (prevByte == 0x26 || prevByte == 0x2E || prevByte == 0x36 || prevByte == 0x3E ||
            prevByte == 0x64 || prevByte == 0x65 || prevByte == 0xF0) return false;
    }

    return prevByte == 0xCC || prevByte == 0xC3 || prevByte == 0xE9 || prevByte == 0xEB;
}

// Checks if the first byte at an address looks like a plausible function
// entry point. Filters out bytes that are never valid instruction starts
// in x86-64 mode, or that strongly indicate non-code (0x00 0xFF padding).
static bool isPlausibleFunctionPrologue(const uint8_t fb) {
    // Explicitly reject non-instruction bytes
    if (fb == 0x00 || fb == 0xFF) return false;
    // int3 padding
    if (fb == 0xCC) return false;
    return true;
}

bool DataSectionFunctionScannerAnalyzer::added(Program* program, const AddressSetView& set,
                                               TaskMonitor* monitor, MessageLog& log) {
    if (!program || !monitor) return false;
    monitor->setMessage("Scanning data sections for code-referencing pointers...");

    Memory* memory = program->getMemory();
    Listing* listing = program->getListing();
    FunctionManager* funcMgr = program->getFunctionManager();
    if (!memory || !listing || !funcMgr) return true;

    // Precompute executable block ranges for O(log N) "is executable" checks
    std::vector<ExecBlockRange> execBlocks;
    for (auto* block : memory->getBlocks()) {
        if (block->isExecute() && block->isInitialized()) {
            execBlocks.push_back({static_cast<uint64_t>(block->getStart().getOffset()),
                                  static_cast<uint64_t>(block->getEnd().getOffset())});
        }
    }
    std::sort(execBlocks.begin(), execBlocks.end(),
              [](const ExecBlockRange& a, const ExecBlockRange& b) { return a.start < b.start; });

    uint64_t imageBase = static_cast<uint64_t>(program->getImageBase().getOffset());
    AddressSpace* defaultSpace = const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());

    // Determine if we're in 64-bit mode for x86 prefix-based rejection.
    std::string langId = program->getLanguageID().getIdAsString();
    std::string langLower = langId;
    std::transform(langLower.begin(), langLower.end(), langLower.begin(), ::tolower);
    bool is64Bit = (langLower.find("64") != std::string::npos) &&
                   (langLower.find("x86") != std::string::npos || langLower.find("i386") != std::string::npos);

    // Precompute .pdata ranges to reject candidates inside guaranteed function
    // boundaries from the PE exception handler table. This prevents creating
    // func_data entries at mid-function addresses that would confuse the decompiler.
    struct PdataRange { uint64_t begin; uint64_t end; };
    std::vector<PdataRange> pdataRanges;
    {
        MemoryBlock* pdataBlock = memory->getBlock(".pdata");
        if (pdataBlock && pdataBlock->isInitialized()) {
            Address pstart = pdataBlock->getStart();
            Address pend = pdataBlock->getEnd();
            if (pstart.isValid() && pend.isValid()) {
                uint64_t psize = pend.getOffset() - pstart.getOffset() + 1;
                if (psize >= 12 && psize <= 1024 * 1024) {
                    std::vector<uint8_t> pbuf(static_cast<size_t>(psize));
                    int pread = pdataBlock->getBytes(pstart, pbuf.data(), static_cast<int>(pbuf.size()));
                    if (pread >= 12) {
                        for (uint64_t off = 0; off <= static_cast<uint64_t>(pread) - 12; off += 12) {
                            uint32_t beginRva = *reinterpret_cast<const uint32_t*>(pbuf.data() + off);
                            uint32_t endRva = *reinterpret_cast<const uint32_t*>(pbuf.data() + off + 4);
                            if (beginRva != 0 && endRva > beginRva) {
                                uint64_t beginAddr = imageBase + beginRva;
                                uint64_t endAddr = imageBase + endRva;
                                pdataRanges.push_back({beginAddr, endAddr});
                            }
                        }
                    }
                }
            }
        }
        std::sort(pdataRanges.begin(), pdataRanges.end(),
                  [](const PdataRange& a, const PdataRange& b) { return a.begin < b.begin; });
        if (!pdataRanges.empty()) {
            Msg::debug(getName(), "Loaded " + std::to_string(pdataRanges.size()) +
                       " .pdata ranges for overlap filtering");
        }
    }

    // Lambda: filter candidates and create functions for unique .text targets.
    // If limit > 0, stops after that many new functions; if limit == 0, unlimited.
    auto scanCandidates = [&](std::vector<uint64_t> cand, int limit) -> int {
        std::sort(cand.begin(), cand.end());
        cand.erase(std::unique(cand.begin(), cand.end()), cand.end());

        int created = 0;
        for (uint64_t tgt : cand) {
            if (monitor->isCancelled()) break;
            if (limit > 0 && created >= limit) break;
            if (tgt == imageBase) continue;

            const ExecBlockRange* eb = findExecBlock(execBlocks, tgt);
            if (!eb) continue;

            // Reject candidates inside .pdata function ranges.
            if (!pdataRanges.empty()) {
                auto prIt = std::lower_bound(pdataRanges.begin(), pdataRanges.end(), tgt,
                    [](const PdataRange& r, uint64_t v) { return r.end <= v; });
                if (prIt != pdataRanges.end() && prIt->begin <= tgt && tgt < prIt->end) {
                    Msg::debug(getName(), "Rejected 0x" + std::to_string(tgt) +
                               ": inside pdata [0x" + std::to_string(prIt->begin) +
                               "-0x" + std::to_string(prIt->end) + ")");
                    continue;
                }
            }

            Address targetAddr(defaultSpace, static_cast<int64_t>(tgt));
            if (funcMgr->getFunctionAt(targetAddr)) continue;
            if (funcMgr->getFunctionContaining(targetAddr)) continue;
            if (!listing->isUndefined(targetAddr)) continue;

            try {
                uint8_t fb[3] = {0, 0, 0};
                memory->getBytes(targetAddr, fb, 3);
                if (!isPlausibleFunctionPrologue(fb[0])) continue;
                // Reject multi-byte NOP alignment padding (0F 1F ...)
                // which is the standard x86-64 alignment NOP sequence
                if (fb[0] == 0x0F && fb[1] == 0x1F) continue;
            } catch (...) { continue; }

            if (!isAtFunctionBoundary(memory, targetAddr, is64Bit)) {
                uint8_t pb = 0;
                try { memory->getBytes(targetAddr.subtract(1), &pb, 1); } catch (...) {}
                Msg::debug(getName(), "Rejected 0x" + std::to_string(tgt) +
                           ": prev=0x" + std::to_string(pb) +
                           " not a function boundary (0xCC,0xC3,0xE9,0xEB)");
                continue;
            }

            try {
                AddressSet body(targetAddr, targetAddr);
                uint8_t prologue[4] = {0,0,0,0};
                try { memory->getBytes(targetAddr, prologue, 4); } catch (...) {}
                funcMgr->createFunction("func_data_0x" + std::to_string(tgt),
                                        targetAddr, body, SourceType::ANALYSIS);
                Msg::debug(getName(), "Created func_data_0x" + std::to_string(tgt) +
                           " at 0x" + std::to_string(tgt) +
                           " prologue: " + std::to_string(prologue[0]) + " " +
                           std::to_string(prologue[1]) + " " +
                           std::to_string(prologue[2]) + " " +
                           std::to_string(prologue[3]));
                ++created;
            } catch (const std::exception&) {
                Msg::debug(getName(), "Failed to create func at 0x" + std::to_string(tgt));
            }
        }
        return created;
    };

    // PHASE 1: collect 8-byte and 4-byte pointer candidates from non-.rdata
    // data sections. Capped at MAX_FOUND because these could be spurious.
    static constexpr int MAX_FOUND = 10000;
    int genericFound = 0;

    {
        auto ptr8 = collect8BytePointers(memory, monitor);
        auto rva4 = collect4ByteRVAs(memory, monitor, imageBase);
        std::vector<uint64_t> all;
        all.reserve(ptr8.size() + rva4.size());
        all.insert(all.end(), ptr8.begin(), ptr8.end());
        all.insert(all.end(), rva4.begin(), rva4.end());
        genericFound = scanCandidates(std::move(all), MAX_FOUND);
    }

    // PHASE 2: scan .rdata specifically for 8-byte pointer targets in .text.
    // Many are COM/C++ vtable entries — strong evidence, but .rdata also
    // contains string tables, import data, etc., so cap candidates.
    int rdataFound = 0;
    {
        std::vector<uint64_t> rdataCandidates;
        rdataCandidates.reserve(2048);

        for (auto* block : memory->getBlocks()) {
            if (monitor->isCancelled()) break;
            std::string bname = block->getName();
            if (bname != ".rdata" && bname != "rdata") continue;
            if (!block->isRead() || !block->isInitialized()) continue;

            Address bstart = block->getStart();
            Address bend = block->getEnd();
            if (!bstart.isValid() || !bend.isValid()) continue;
            uint64_t bsize = (bend.getOffset() - bstart.getOffset() + 1);
            if (bsize > 16 * 1024 * 1024) bsize = 16 * 1024 * 1024;
            if (bsize < 8) continue;

            std::vector<uint8_t> buf(static_cast<size_t>(bsize));
            int bread = block->getBytes(bstart, buf.data(), static_cast<int>(buf.size()));
            if (bread < 8) continue;
            bsize = static_cast<uint64_t>(bread);

            for (uint64_t off = 0; off <= bsize - 8; off += 8) {
                uint64_t val = *reinterpret_cast<const uint64_t*>(buf.data() + off);
                if (val == 0 || val == UINT64_MAX) continue;
                if ((val & 1) != 0) continue;
                rdataCandidates.push_back(val);
            }
        }

        rdataFound = scanCandidates(std::move(rdataCandidates), MAX_FOUND);
    }

    int totalFound = genericFound + rdataFound;
    if (totalFound > 0) {
        Msg::info(getName(), "Found " + std::to_string(totalFound) +
                  " function starts from data section pointers (" +
                  std::to_string(genericFound) + " generic, " +
                  std::to_string(rdataFound) + " .rdata).");
    }
    return true;
}

} // namespace ghidra
