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
// E9 (jmp), or the address should be the start of the executable block.
static bool isAtFunctionBoundary(Memory* memory, const Address& addr) {
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

    return prevByte == 0xCC || prevByte == 0xC3 || prevByte == 0xE9 || prevByte == 0xEB ||
           prevByte == 0x90 || prevByte == 0x00;
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

            Address targetAddr(defaultSpace, static_cast<int64_t>(tgt));
            if (funcMgr->getFunctionAt(targetAddr)) continue;
            if (funcMgr->getFunctionContaining(targetAddr)) continue;
            if (!listing->isUndefined(targetAddr)) continue;

            try {
                uint8_t fb = 0;
                memory->getBytes(targetAddr, &fb, 1);
                if (fb == 0xCC) continue;
            } catch (...) { continue; }

            try {
                AddressSet body(targetAddr, targetAddr);
                funcMgr->createFunction("func_data_0x" + std::to_string(tgt),
                                        targetAddr, body, SourceType::ANALYSIS);
                ++created;
            } catch (const std::exception&) {}
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
    // These are COM/C++ vtable entries — strong deterministic evidence.
    // No cap: even single-entry vtable pointers are valid function references.
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

        rdataFound = scanCandidates(std::move(rdataCandidates), 0);
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
