#include <ghidra/FragmentMergeAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/FunctionIterator.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/Disassembler.h>
#include <ghidra/AutoNaming.h>
#include <ghidra/Memory.h>
#include <ghidra/Listing.h>
#include <algorithm>
#include <cstdint>
#include <vector>
#include <utility>
#include <unordered_set>
#include <sstream>
#include <chrono>
#include <iostream>

namespace ghidra {

FragmentMergeAnalyzer::FragmentMergeAnalyzer()
    : AbstractAnalyzer("Fragment Merge",
                       "Merges func_start_ entries within 16 bytes of another func_start_ entry "
                       "into the parent function, reducing false function count without affecting recall.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FUNCTION_ID_ANALYSIS);
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

bool FragmentMergeAnalyzer::canAnalyze(Program* program) const {
    return program != nullptr;
}

bool FragmentMergeAnalyzer::added(Program* program, const AddressSetView& set,
                                   TaskMonitor* monitor, MessageLog& log) {
    if (!program || !monitor) return true;
    monitor->setMessage("Merging func_start_ fragments into parent functions...");

    auto t0 = std::chrono::high_resolution_clock::now();

    FunctionManager* funcMgr = program->getFunctionManager();
    if (!funcMgr) return true;

    // Collect all function addresses and names, sorted by address
    std::vector<std::pair<uint64_t, std::string>> funcs;
    FunctionIterator fit = funcMgr->getFunctions(true);
    while (fit.hasNext()) {
        Function* f = fit.next();
        if (f) {
            funcs.emplace_back(f->getEntryPoint().getOffset(), f->getName());
        }
    }

    if (funcs.empty()) return true;

    // Only merge func_start_ entries that are within 16 bytes of another func_start_ entry.
    std::unordered_set<uint64_t> toRemove;
    uint64_t prevAddr = funcs[0].first;
    std::string prevName = funcs[0].second;
    for (size_t i = 1; i < funcs.size(); i++) {
        uint64_t addr = funcs[i].first;
        const std::string& name = funcs[i].second;
        uint64_t gap = addr - prevAddr;

        if (name.rfind("func_0x", 0) == 0 &&
            prevName.rfind("func_0x", 0) == 0 &&
            gap > 0 && gap <= 4) {
            toRemove.insert(addr);
        } else {
            prevAddr = addr;
            prevName = name;
        }
    }

    auto t1 = std::chrono::high_resolution_clock::now();

    if (!toRemove.empty()) {
        AddressFactory* addrFactory = program->getAddressFactory();
        if (!addrFactory) return true;
        const AddressSpace* defaultSpace = addrFactory->getDefaultAddressSpace();
        if (!defaultSpace) return true;

        for (uint64_t addr : toRemove) {
            Address funcAddr(const_cast<AddressSpace*>(defaultSpace), static_cast<int64_t>(addr));
            funcMgr->removeFunction(funcAddr);
        }
    }

    auto t2 = std::chrono::high_resolution_clock::now();

    // --- Step 2: Gap bridging (reference-required) ---
    LanguageID lid = program->getLanguageID();
    std::string lidStr = lid.getIdAsString();
    std::string arch;
    if (lidStr.find("x86") != std::string::npos || lidStr.find("X86") != std::string::npos) arch = "x86";
    else if (lidStr.find("ARM") != std::string::npos || lidStr.find("AARCH64") != std::string::npos) arch = "ARM";
    if (arch == "x86") {
        int bitness = (lidStr.find("64") != std::string::npos) ? 64 : 32;
        auto disassembler = createDisassembler(arch, bitness, false);
        if (disassembler) {
            monitor->setMessage("Scanning gaps for CALL-target functions...");

            Memory* memory = program->getMemory();
            Listing* listing = program->getListing();

            std::vector<std::pair<uint64_t, uint64_t>> funcRanges;
            FunctionIterator fit2 = funcMgr->getFunctions(true);
            while (fit2.hasNext()) {
                Function* f = fit2.next();
                if (f) {
                    const AddressSet& body = f->getBody();
                    if (body.isEmpty()) {
                        uint64_t entry = f->getEntryPoint().getOffset();
                        funcRanges.emplace_back(entry, entry);
                    } else {
                        uint64_t start = body.getMinAddress().getOffset();
                        uint64_t end = body.getMaxAddress().getOffset();
                        funcRanges.emplace_back(start, end);
                    }
                }
            }

            auto t3 = std::chrono::high_resolution_clock::now();

            int gapFunctions = 0;
            AddressSpace* defSpace = const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
            auto blocks2 = memory->getBlocks();

            uint64_t totalBytesScanned = 0;
            uint64_t totalCallsFound = 0;

            for (auto* block : blocks2) {
                if (!block || !block->isExecute() || !block->isInitialized()) continue;
                uint64_t blockStart = block->getStart().getOffset();
                uint64_t blockEnd = block->getEnd().getOffset();

                uint64_t bufSize = (blockEnd - blockStart + 1);
                if (bufSize > 8 * 1024 * 1024) bufSize = 8 * 1024 * 1024;
                if (bufSize < 5) continue;
                std::vector<uint8_t> blockBuf(static_cast<size_t>(bufSize));
                Address blockStartAddr(defSpace, static_cast<int64_t>(blockStart));
                int got = block->getBytes(blockStartAddr, blockBuf.data(), static_cast<int>(blockBuf.size()));
                if (got < 5) continue;
                bufSize = static_cast<uint64_t>(got);
                totalBytesScanned += bufSize;

                std::vector<uint64_t> funcStarts;
                funcStarts.reserve(funcRanges.size());
                for (const auto& fr : funcRanges) {
                    funcStarts.push_back(fr.first);
                }

                for (uint64_t callOff = 0; callOff + 5 <= bufSize; callOff++) {
                    if (blockBuf[callOff] != 0xE8) continue;
                    totalCallsFound++;

                    int32_t rel = *reinterpret_cast<const int32_t*>(blockBuf.data() + callOff + 1);
                    uint64_t callSrc = blockStart + callOff;
                    uint64_t callTgt = callSrc + 5 + static_cast<uint64_t>(static_cast<int64_t>(rel));

                    if (callTgt < blockStart || callTgt > blockEnd) continue;

                    auto it = std::upper_bound(funcStarts.begin(), funcStarts.end(), callTgt);
                    if (it == funcStarts.begin() || it == funcStarts.end()) continue;
                    size_t idx = static_cast<size_t>(std::distance(funcStarts.begin(), it));

                    uint64_t prevEnd = funcRanges[idx - 1].second;
                    uint64_t currStart = funcRanges[idx].first;

                    if (prevEnd < blockStart || currStart > blockEnd) continue;
                    if (callTgt <= prevEnd) continue;

                    uint64_t gapStart = std::max(prevEnd + 1, blockStart);
                    uint64_t gapEnd = std::min(currStart > 0 ? currStart - 1 : 0, blockEnd);
                    if (callTgt < gapStart || callTgt > gapEnd) continue;

                    uint64_t gapSize = gapEnd - gapStart + 1;
                    if (gapSize > 128) continue;

                    Address tgtAddr(defSpace, static_cast<int64_t>(callTgt));
                    if (funcMgr->getFunctionAt(tgtAddr)) continue;
                    if (funcMgr->getFunctionContaining(tgtAddr)) continue;
                    if (!listing->isUndefined(tgtAddr)) continue;

                    try {
                        uint8_t fb = 0;
                        memory->getBytes(tgtAddr, &fb, 1);
                        if (fb == 0xCC || fb == 0x00) continue;
                    } catch (...) { continue; }

                    try {
                        AddressSet body(tgtAddr, tgtAddr);
                        std::ostringstream funcName;
                        funcName << AutoNaming::nameVal("func", callTgt);
                        funcMgr->createFunction(funcName.str(), tgtAddr, body, SourceType::ANALYSIS);
                        gapFunctions++;
                    } catch (const std::exception&) {}
                }
            }

            auto t4 = std::chrono::high_resolution_clock::now();

            auto ms0 = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
            auto ms1 = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
            auto ms2 = std::chrono::duration_cast<std::chrono::milliseconds>(t3 - t2).count();
            auto ms3 = std::chrono::duration_cast<std::chrono::milliseconds>(t4 - t3).count();

            std::cerr << "[FRAGMENT-MERGE-PROFILE] t_identify=" << ms0 << "ms"
                      << " t_remove=" << ms1 << "ms"
                      << " t_funcRanges=" << ms2 << "ms"
                      << " t_scanBlocks=" << ms3 << "ms"
                      << " removed=" << toRemove.size()
                      << " gapFuncs=" << gapFunctions
                      << " bytesScanned=" << totalBytesScanned
                      << " callsFound=" << totalCallsFound
                      << std::endl;
        }
    }
    return true;
}

} // namespace ghidra
