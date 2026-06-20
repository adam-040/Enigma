#include <ghidra/AggressiveRecoveryAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/ProgramDB.h>
#include <ghidra/Language.h>
#include <ghidra/Disassembler.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/BookmarkManager.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/Options.h>
#include <ghidra/SourceType.h>
#include <ghidra/Msg.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/Reference.h>
#include <ghidra/RefType.h>

#include <string>
#include <vector>
#include <cstdint>
#include <cctype>
#include <algorithm>
#include <sstream>
#include <unordered_set>

namespace ghidra {

AggressiveRecoveryAnalyzer::AggressiveRecoveryAnalyzer()
    : AbstractAnalyzer(
          "Aggressive Recovery Analyzer",
          "Phase B: recovers functions from orphan islands, gap CALL targets, "
          "and tiny helpers using heuristic disassembly. Disabled by default. "
          "Run only after Phase A pipeline completes.",
          AnalyzerType::BYTE_ANALYZER) {
    setDefaultEnablement(false);
    setSupportsOneTimeAnalysis(true);
    setPriority(AnalysisPriority::FUNCTION_ID_ANALYSIS.after());
}

void AggressiveRecoveryAnalyzer::registerOptions(Options& options, Program* program) {
    options.registerBool("Create Analysis Bookmarks", true,
                         "Create bookmark at each discovered region");
    options.registerInt("Max Orphan Candidates", 500,
                        "Maximum orphan island candidates to process");
    options.registerInt("Confidence Threshold", 10,
                        "Minimum confidence score to create a function");
}

void AggressiveRecoveryAnalyzer::optionsChanged(Options& options, Program* program) {
    if (options.hasOption("Create Analysis Bookmarks"))
        createBookmarksEnabled_ = options.getBool("Create Analysis Bookmarks");
    if (options.hasOption("Max Orphan Candidates"))
        maxOrphanCandidates_ = options.getInt("Max Orphan Candidates");
    if (options.hasOption("Confidence Threshold"))
        confidenceThreshold_ = options.getInt("Confidence Threshold");
}

int AggressiveRecoveryAnalyzer::classifyScore(int total) const {
    if (total >= 80) return 80;
    if (total >= 40) return 40;
    if (total >= 10) return 10;
    return 0;
}

std::string AggressiveRecoveryAnalyzer::classifyLevel(int total) const {
    if (total >= 80) return "HIGH";
    if (total >= 40) return "MEDIUM";
    if (total >= 10) return "LOW";
    return "SPECULATIVE";
}

int AggressiveRecoveryAnalyzer::scoreCandidate(
    uint64_t addr, int instrCount, const std::string& lastMnemonic,
    bool hasCallRefs, bool hasDataRefs,
    bool inPdata, bool inExport, bool inVtableRun,
    uint64_t nearestDist)
{
    int score = 0;

    if (inPdata) score += SCORE_PDATA_ENTRY;
    if (inExport) score += SCORE_EXPORT_TABLE;

    if (hasCallRefs) {
        score += SCORE_SINGLE_CALL_REF;
    }

    if (hasDataRefs) score += SCORE_RDATA_8BYTE_PTR;

    if (inVtableRun) score += SCORE_VTABLE_RUN;

    // Ending-based evidence
    if (lastMnemonic == "ret" || lastMnemonic == "retn") {
        score += SCORE_VALID_RET_ENDING;
    } else if (lastMnemonic == "int3") {
        score += SCORE_VALID_INT3_ENDING;
    } else if (lastMnemonic == "jmp") {
        score += SCORE_VALID_JMP_ENDING;
    } else if (lastMnemonic == "call" || lastMnemonic == "je" ||
               lastMnemonic == "jne" || lastMnemonic == "jg" ||
               lastMnemonic == "jl" || lastMnemonic == "jge" ||
               lastMnemonic == "jle" || lastMnemonic == "ja" ||
               lastMnemonic == "jb" || lastMnemonic == "jae" ||
               lastMnemonic == "jbe" || lastMnemonic == "js" ||
               lastMnemonic == "jns") {
        score += SCORE_PENALTY_TRUNCATION;
    }

    // Proximity bonus: close to known function = more credible
    if (nearestDist <= 64 && score > SCORE_EXECUTABLE_BYTES_ONLY) {
        score += 5;
    }

    // Base score for any executable bytes
    if (score == 0) score = SCORE_EXECUTABLE_BYTES_ONLY;

    return std::max(0, score);
}

int AggressiveRecoveryAnalyzer::scanOrphanIslands(
    Program* program, Memory* memory, Listing* listing,
    FunctionManager* funcMgr, TaskMonitor* monitor,
    std::vector<FunctionEvidence>& candidates)
{
    if (monitor) monitor->setMessage(getName() + ": Scanning orphan islands...");

    Language* lang = program->getLanguage();
    if (!lang) return 0;

    LanguageID langId = lang->getLanguageID();
    std::string lidStr = langId.getIdAsString();
    std::string arch;
    if (lidStr.find("x86") != std::string::npos || lidStr.find("X86") != std::string::npos)
        arch = "x86";
    else if (lidStr.find("ARM") != std::string::npos || lidStr.find("AARCH64") != std::string::npos)
        arch = "ARM";
    else
        arch = "x86";

    int bitness = lang->getDefaultSpace()->getSize();
    auto disassembler = createDisassembler(arch, bitness, lang->isBigEndian());
    if (!disassembler) return 0;

    // Collect all function address ranges for proximity checks
    std::vector<uint64_t> funcEntries;
    FunctionIterator fit = funcMgr->getFunctions(true);
    while (fit.hasNext()) {
        Function* f = fit.next();
        if (f) funcEntries.push_back(f->getEntryPoint().getOffset());
    }
    std::sort(funcEntries.begin(), funcEntries.end());

    int islandCount = 0;
    AddressSpace* defSpace = const_cast<AddressSpace*>(
        program->getAddressFactory()->getDefaultAddressSpace());

    for (auto* block : memory->getBlocks()) {
        if (monitor && monitor->isCancelled()) break;
        if (!block->isExecute() || !block->isInitialized()) continue;

        uint64_t blockStart = block->getStart().getOffset();
        uint64_t blockEnd = block->getEnd().getOffset();
        uint64_t blockSize = blockEnd - blockStart + 1;

        for (uint64_t off = 0; off < blockSize && islandCount < maxOrphanCandidates_; ) {
            if (monitor && monitor->isCancelled()) break;

            Address addr(defSpace, static_cast<int64_t>(blockStart + off));

            // Skip if already defined or in a function
            if (!listing->isUndefined(addr)) { off++; continue; }
            if (funcMgr->getFunctionAt(addr)) { off++; continue; }
            if (funcMgr->getFunctionContaining(addr)) { off++; continue; }

            // Check first byte
            uint8_t fb = 0;
            try {
                memory->getBytes(addr, &fb, 1);
            } catch (...) { off++; continue; }

            if (fb == 0xCC || fb == 0x00 || fb == 0xFF || fb == 0xEA) {
                off++; continue;
            }

            // Read bytes for disassembly (max 256)
            uint64_t remaining = blockEnd - (blockStart + off) + 1;
            uint64_t readSz = std::min<uint64_t>(remaining, 256);
            std::vector<uint8_t> bytes(static_cast<size_t>(readSz));
            try {
                int got = memory->getBytes(addr, bytes.data(), static_cast<int>(readSz));
                if (got < 1) { off++; continue; }
                bytes.resize(static_cast<size_t>(got));
            } catch (...) { off++; continue; }

            // Disassemble up to 30 instructions
            auto instrs = disassembler->disassembleRange(bytes, blockStart + off,
                                                         bytes.size(), 30);

            if (instrs.empty()) { off++; continue; }

            // Must have at least 2 instructions to be viable
            if (instrs.size() < 2) { off++; continue; }

            int totalLen = 0;
            for (auto& di : instrs) totalLen += di.length;

            std::string firstMnem = instrs[0].mnemonic;
            std::string lastMnem = instrs.back().mnemonic;

            // Must end with RET, RETN, INT3, or JMP (tail call)
            if (lastMnem != "ret" && lastMnem != "retn" &&
                lastMnem != "int3" && lastMnem != "jmp" &&
                lastMnem != "retf") {
                off++; continue;
            }

            // Proximity to nearest known function
            uint64_t entryAddr = blockStart + off;
            uint64_t nearestDist = UINT64_MAX;
            auto it = std::lower_bound(funcEntries.begin(), funcEntries.end(), entryAddr);
            if (it != funcEntries.end()) {
                nearestDist = (*it > entryAddr) ? (*it - entryAddr) : 0;
            }
            if (it != funcEntries.begin()) {
                auto prev = it - 1;
                nearestDist = std::min(nearestDist, entryAddr - *prev);
            }

            // Check for references
            bool hasCallRefs = false;
            bool hasDataRefs = false;
            ReferenceManager* refMgr = program->getReferenceManager();
            if (refMgr) {
                auto refs = refMgr->getReferencesTo(addr);
                for (Reference* ref : refs) {
                    if (!ref) continue;
                    if (ref->getReferenceType()->isCall()) hasCallRefs = true;
                    if (ref->getReferenceType()->isData()) hasDataRefs = true;
                }
            }

            int score = scoreCandidate(entryAddr, (int)instrs.size(), lastMnem,
                                       hasCallRefs, hasDataRefs,
                                       false, false, false, nearestDist);

            FunctionEvidence ev;
            ev.address = entryAddr;
            ev.score = score;
            ev.classification = classifyLevel(score);
            ev.instrCount = (int)instrs.size();
            ev.firstMnemonic = firstMnem;
            ev.lastMnemonic = lastMnem;
            ev.nearestEnigmaDist = nearestDist;

            std::stringstream ss;
            ss << "orphan_island_" << "0x" << std::hex << std::nouppercase << entryAddr;
            ev.evidence.push_back("orphan island: " + std::to_string(instrs.size()) + " instrs");
            ev.evidence.push_back("ends: " + lastMnem);
            if (hasCallRefs) ev.evidence.push_back("has CALL refs");
            candidates.push_back(ev);

            // Only create function if threshold met
            if (score >= confidenceThreshold_) {
                try {
                    AddressSet body(addr, addr.add(totalLen - 1));
                    funcMgr->createFunction(ss.str(), addr, body, SourceType::ANALYSIS);
                    islandCount++;

                    if (createBookmarksEnabled_) {
                        BookmarkManager* bmMgr = program->getBookmarkManager();
                        if (bmMgr) {
                            bmMgr->setBookmark(addr, "Analysis",
                                               "Aggressive recovery: " +
                                               std::to_string(instrs.size()) +
                                               " instrs, score=" + std::to_string(score));
                        }
                    }
                } catch (const std::exception&) {}
            }

            off += static_cast<uint64_t>(totalLen);
        }
    }

    return islandCount;
}

int AggressiveRecoveryAnalyzer::scanGapCallTargets(
    Program* program, Memory* memory, Listing* listing,
    FunctionManager* funcMgr, TaskMonitor* monitor,
    std::vector<FunctionEvidence>& candidates)
{
    if (monitor) monitor->setMessage(getName() + ": Scanning gap CALL targets...");

    // Collect function ranges
    std::vector<std::pair<uint64_t, uint64_t>> funcRanges;
    FunctionIterator fit = funcMgr->getFunctions(true);
    while (fit.hasNext()) {
        Function* f = fit.next();
        if (f) {
            const AddressSet& body = f->getBody();
            if (body.isEmpty()) {
                uint64_t entry = f->getEntryPoint().getOffset();
                funcRanges.emplace_back(entry, entry);
            } else {
                funcRanges.emplace_back(body.getMinAddress().getOffset(),
                                        body.getMaxAddress().getOffset());
            }
        }
    }

    // Scan gaps up to 256 bytes for CALL targets (Phase A uses 128, this is aggressive)
    int gapFuncs = 0;
    AddressSpace* defSpace = const_cast<AddressSpace*>(
        program->getAddressFactory()->getDefaultAddressSpace());

    for (auto* block : memory->getBlocks()) {
        if (monitor && monitor->isCancelled()) break;
        if (!block->isExecute() || !block->isInitialized()) continue;

        uint64_t blockStart = block->getStart().getOffset();
        uint64_t blockEnd = block->getEnd().getOffset();

        uint64_t bufSize = blockEnd - blockStart + 1;
        if (bufSize > 8 * 1024 * 1024) bufSize = 8 * 1024 * 1024;
        if (bufSize < 5) continue;

        std::vector<uint8_t> blockBuf(static_cast<size_t>(bufSize));
        Address blockStartAddr(defSpace, static_cast<int64_t>(blockStart));
        int got = 0;
        try {
            got = memory->getBytes(blockStartAddr, blockBuf.data(), static_cast<int>(blockBuf.size()));
        } catch (...) { continue; }
        if (got < 5) continue;
        bufSize = static_cast<uint64_t>(got);

        for (size_t i = 1; i < funcRanges.size(); i++) {
            uint64_t prevEnd = funcRanges[i - 1].second;
            uint64_t currStart = funcRanges[i].first;

            if (prevEnd < blockStart || currStart > blockEnd) continue;
            uint64_t gapStart = std::max(prevEnd + 1, blockStart);
            uint64_t gapEnd = std::min(currStart > 0 ? currStart - 1 : 0, blockEnd);
            if (gapStart >= gapEnd) continue;

            uint64_t gapSize = gapEnd - gapStart + 1;
            if (gapSize > 256) continue; // Aggressive: wider window than Phase A (128)

            for (uint64_t callOff = 0; callOff + 5 <= bufSize; callOff++) {
                if (blockBuf[callOff] != 0xE8) continue;

                int32_t rel = *reinterpret_cast<const int32_t*>(blockBuf.data() + callOff + 1);
                uint64_t callSrc = blockStart + callOff;
                uint64_t callTgt = callSrc + 5 + static_cast<uint64_t>(static_cast<int64_t>(rel));

                if (callTgt < gapStart || callTgt > gapEnd) continue;

                Address tgtAddr(defSpace, static_cast<int64_t>(callTgt));
                if (funcMgr->getFunctionAt(tgtAddr)) continue;
                if (funcMgr->getFunctionContaining(tgtAddr)) continue;
                if (!listing->isUndefined(tgtAddr)) continue;

                uint8_t fb = 0;
                try {
                    memory->getBytes(tgtAddr, &fb, 1);
                    if (fb == 0xCC || fb == 0x00) continue;
                } catch (...) { continue; }

                // Confidence: CALL ref in gap is inherently MEDIUM evidence
                int score = SCORE_SINGLE_CALL_REF;
                // Bonus if close to something
                if (gapSize <= 64) score += 10;

                FunctionEvidence ev;
                ev.address = callTgt;
                ev.score = score;
                ev.classification = classifyLevel(score);
                ev.instrCount = 0;
                ev.firstMnemonic = "gap_call";
                ev.lastMnemonic = "gap_call";
                ev.nearestEnigmaDist = gapSize;
                ev.evidence.push_back("CALL target in gap");
                ev.evidence.push_back("gap size: " + std::to_string(gapSize));
                candidates.push_back(ev);

                try {
                    AddressSet body(tgtAddr, tgtAddr);
                    std::ostringstream funcName;
                    funcName << "func_gap_agg_0x" << std::hex << std::nouppercase << callTgt;
                    funcMgr->createFunction(funcName.str(), tgtAddr, body, SourceType::ANALYSIS);
                    gapFuncs++;
                } catch (const std::exception&) {}
            }
        }
    }

    return gapFuncs;
}

int AggressiveRecoveryAnalyzer::scanTinyHelpers(
    Program* program, Memory* memory, Listing* listing,
    FunctionManager* funcMgr, TaskMonitor* monitor,
    std::vector<FunctionEvidence>& candidates)
{
    if (monitor) monitor->setMessage(getName() + ": Scanning tiny helpers...");

    Language* lang = program->getLanguage();
    if (!lang) return 0;

    LanguageID langId = lang->getLanguageID();
    std::string lidStr = langId.getIdAsString();
    std::string arch;
    if (lidStr.find("x86") != std::string::npos || lidStr.find("X86") != std::string::npos)
        arch = "x86";
    else if (lidStr.find("ARM") != std::string::npos || lidStr.find("AARCH64") != std::string::npos)
        arch = "ARM";
    else
        arch = "x86";

    int bitness = lang->getDefaultSpace()->getSize();
    auto disassembler = createDisassembler(arch, bitness, lang->isBigEndian());
    if (!disassembler) return 0;

    int tinyCount = 0;
    AddressSpace* defSpace = const_cast<AddressSpace*>(
        program->getAddressFactory()->getDefaultAddressSpace());

    for (auto* block : memory->getBlocks()) {
        if (monitor && monitor->isCancelled()) break;
        if (!block->isExecute() || !block->isInitialized()) continue;

        uint64_t blockStart = block->getStart().getOffset();
        uint64_t blockEnd = block->getEnd().getOffset();
        uint64_t blockSize = blockEnd - blockStart + 1;

        for (uint64_t off = 0; off < blockSize; off++) {
            if (monitor && monitor->isCancelled()) break;

            Address addr(defSpace, static_cast<int64_t>(blockStart + off));
            if (!listing->isUndefined(addr)) continue;
            if (funcMgr->getFunctionAt(addr)) continue;
            if (funcMgr->getFunctionContaining(addr)) continue;

            uint8_t fb = 0;
            try { memory->getBytes(addr, &fb, 1); } catch (...) { continue; }
            if (fb == 0xCC || fb == 0x00) continue;

            uint64_t remaining = blockEnd - (blockStart + off) + 1;
            uint64_t readSz = std::min<uint64_t>(remaining, 32);
            std::vector<uint8_t> bytes(static_cast<size_t>(readSz));
            try {
                int got = memory->getBytes(addr, bytes.data(), static_cast<int>(readSz));
                if (got < 1) continue;
                bytes.resize(static_cast<size_t>(got));
            } catch (...) { continue; }

            auto instrs = disassembler->disassembleRange(bytes, blockStart + off,
                                                         bytes.size(), 6);
            if (instrs.empty()) continue;

            // Tiny helper: 1-4 instructions ending in RET/RETN
            if (instrs.size() > 4) continue;

            std::string lastMnem = instrs.back().mnemonic;
            if (lastMnem != "ret" && lastMnem != "retn") continue;

            // Must fully consume the sequence
            int totalLen = 0;
            for (auto& di : instrs) totalLen += di.length;

            // Check proximity to known functions
            uint64_t entryAddr = blockStart + off;
            Function* containing = funcMgr->getFunctionContaining(addr);
            if (containing) continue; // skip if inside a function

            // Confidence score
            int score = SCORE_VALID_RET_ENDING;
            if (instrs.size() <= 2) score += 5; // very tiny = higher confidence

            FunctionEvidence ev;
            ev.address = entryAddr;
            ev.score = score;
            ev.classification = classifyLevel(score);
            ev.instrCount = (int)instrs.size();
            ev.firstMnemonic = instrs[0].mnemonic;
            ev.lastMnemonic = lastMnem;
            ev.nearestEnigmaDist = 0;
            ev.evidence.push_back("TINY_HELPER: " + std::to_string(instrs.size()) + " instrs");
            ev.evidence.push_back("ends: " + lastMnem);
            candidates.push_back(ev);

            // Create function
            try {
                AddressSet body(addr, addr.add(totalLen - 1));
                std::ostringstream funcName;
                funcName << "tiny_helper_0x" << std::hex << std::nouppercase << entryAddr;
                funcMgr->createFunction(funcName.str(), addr, body, SourceType::ANALYSIS);
                tinyCount++;

                if (createBookmarksEnabled_) {
                    BookmarkManager* bmMgr = program->getBookmarkManager();
                    if (bmMgr)
                        bmMgr->setBookmark(addr, "Analysis",
                                           "Tiny helper: " + std::to_string(instrs.size()) + " instrs");
                }
            } catch (const std::exception&) {}

            off += static_cast<uint64_t>(totalLen) - 1;
        }
    }

    return tinyCount;
}

bool AggressiveRecoveryAnalyzer::added(Program* program, const AddressSetView& set,
                                        TaskMonitor* monitor, MessageLog& log)
{
    if (!program || !monitor) return false;

    Memory* memory = program->getMemory();
    Listing* listing = program->getListing();
    FunctionManager* funcMgr = program->getFunctionManager();
    if (!memory || !listing || !funcMgr) return true;

    int funcCountBefore = funcMgr->getFunctionCount();
    if (funcCountBefore < 20) {
        log.append(getName(), "Too few functions (" + std::to_string(funcCountBefore) +
                   ") for aggressive recovery. Skipping.");
        return true;
    }

    monitor->setMessage(getName() + ": Phase B aggressive recovery starting...");

    std::vector<FunctionEvidence> candidates;

    int orphanCreated = scanOrphanIslands(program, memory, listing, funcMgr,
                                          monitor, candidates);
    int gapCreated = scanGapCallTargets(program, memory, listing, funcMgr,
                                        monitor, candidates);
    int tinyCreated = scanTinyHelpers(program, memory, listing, funcMgr,
                                      monitor, candidates);

    int totalCreated = orphanCreated + gapCreated + tinyCreated;
    int totalCandidates = (int)candidates.size();
    int funcCountAfter = funcMgr->getFunctionCount();

    // Log summary
    std::stringstream ss;
    ss << getName() << ": Phase B results — "
       << totalCreated << " functions created "
       << "(" << orphanCreated << " orphan islands, "
       << gapCreated << " gap CALL targets, "
       << tinyCreated << " tiny helpers) "
       << "from " << totalCandidates << " candidates. "
       << "Functions: " << funcCountBefore << " -> " << funcCountAfter
       << " (+" << (funcCountAfter - funcCountBefore) << ")";
    Msg::info(getName(), ss.str());

    // Confidence breakdown
    std::unordered_map<std::string, int> levelCounts;
    for (auto& ev : candidates) levelCounts[ev.classification]++;
    std::stringstream detail;
    detail << "Confidence breakdown: ";
    for (auto& [level, count] : levelCounts)
        detail << level << "=" << count << " ";
    Msg::info(getName(), detail.str());

    return true;
}

} // namespace ghidra
