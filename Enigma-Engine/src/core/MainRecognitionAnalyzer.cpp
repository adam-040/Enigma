/// MainRecognitionAnalyzer.cpp
/// Post-analysis pass: identifies user main() / WinMain() by tracing
/// the CRT startup call-graph from the program entry point.
///
/// Strategy (no decompiler required):
///   • Uses the Instruction references stored in the Listing by
///     DisassemblyAnalyzer (UNCONDITIONAL_CALL references) to reconstruct
///     a direct call-graph per function.
///   • Classifies functions whose call graph reaches known CRT import names
///     as "CRT startup" functions.
///   • The non-CRT callee of a CRT startup function that is still unnamed
///     (sub_XXXXXXXX) becomes the "main" candidate.
///
/// Limitations:
///   • Only follows direct (resolved) CALL instructions recorded as
///     operand references.  Indirect calls / thunks are ignored.
///   • Works best with typical MSVC / MinGW CRT startup patterns.

#include <ghidra/MainRecognitionAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/FunctionIterator.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/Symbol.h>
#include <ghidra/SourceType.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/Msg.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/Reference.h>

#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <map>
#include <string>
#include <algorithm>

namespace ghidra {

// -----------------------------------------------------------------------
// Known CRT startup import names — any function that directly calls one
// of these is CRT regardless of its own (possibly stripped) name.
// -----------------------------------------------------------------------
static const std::unordered_set<std::string> kCrtStartupApis = {
    "__getmainargs",   "__wgetmainargs",
    "_initterm",       "_initterm_e",
    "__set_app_type",  "SetUnhandledExceptionFilter",
    "__scrt_initialize_crt", "__scrt_acquire_startup_lock",
    "__scrt_release_startup_lock",
    "exit", "atexit", "_cexit", "_c_exit",
    "__C_specific_handler", "_except_handler4_common",
    "_seh_filter_exe", "__scrt_is_user_crt_exception",
    "__scrt_unhandled_exception_filter",
    "_crt_atexit", "_register_thread_local_exe_atexit_callback",
    "_set_new_mode",  "_set_new_handler",
    "__p___argc", "__p___argv", "__p___wargv", "__p___envp",
    "__p__acmdln", "__p__wcmdln",
    "__initenv", "get_initial_narrow_environment",
    // Common C library import thunks
    "strlen", "strncpy", "strncmp", "strcmp", "strcpy", "strcat",
    "memcpy", "memmove", "memset", "memcmp",
    "malloc", "calloc", "realloc", "free",
    "fprintf", "printf", "sprintf", "snprintf", "vfprintf", "vprintf", "vsprintf",
    "fopen", "fclose", "fread", "fwrite", "fgets", "fputs",
    "abort", "exit", "_exit", "_Exit",
    "signal", "raise",
    "atoi", "atol", "atof", "strtol", "strtoul", "strtod",
    "__iob_func", "_amsg_exit",
    "_beginthreadex", "_endthreadex",
    "InitializeCriticalSection", "EnterCriticalSection", "LeaveCriticalSection",
    "GetLastError", "SetLastError",
    "HeapAlloc", "HeapFree", "GetProcessHeap",
    "VirtualAlloc", "VirtualFree",
    "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "FreeLibrary",
    "GetModuleHandleA", "GetModuleHandleW",
    "MultiByteToWideChar", "WideCharToMultiByte",
    "GetVersionExA", "GetVersionExW", "GetVersion",
    "InterlockedCompareExchange", "InterlockedExchange",
    "QueryPerformanceCounter", "QueryPerformanceFrequency",
    "GetSystemTimeAsFileTime", "GetCurrentProcessId", "GetCurrentThreadId",
    "TerminateProcess", "GetCurrentProcess",
    "UnhandledExceptionFilter", "SetUnhandledExceptionFilter",
    "__set_fmode", "__p__fmode", "__p__commode",
    "_configthreadlocale", "_set_printf_count_output",
    "__stdio_common_vfprintf", "__acrt_iob_func",
};

// -----------------------------------------------------------------------
// CRT name prefixes used when behavioral analysis is unavailable
// -----------------------------------------------------------------------
static const char* const kCrtPrefixes[] = {
    "__scrt_", "__acrt_", "__vcrt_", "_crt",
    "msvcrt_", "_set_se_translator",
    "__mingw_",
    nullptr
};

// -----------------------------------------------------------------------
// Helper: build a name→address and address→name table from SymbolTable
// -----------------------------------------------------------------------
static void buildSymbolMaps(
        Program* program,
        std::unordered_map<uint64_t, std::string>& addrToName,
        std::unordered_map<std::string, uint64_t>& nameToAddr) {

    auto* funcMgr = program->getFunctionManager();
    auto* symTable = program->getSymbolTable();

    // First: populate from function names (primary source for renamed functions)
    if (funcMgr) {
        FunctionIterator fit = funcMgr->getFunctions(true);
        while (fit.hasNext()) {
            Function* f = fit.next();
            if (!f) continue;
            uint64_t off = static_cast<uint64_t>(f->getEntryPoint().getOffset());
            if (off == 0) continue;
            std::string name = f->getName();
            if (!name.empty()) {
                if (addrToName.find(off) == addrToName.end())
                    addrToName[off] = name;
                if (nameToAddr.find(name) == nameToAddr.end())
                    nameToAddr[name] = off;
            }
        }
    }

    // Then: overlay from symbol table (may have additional aliases)
    if (symTable) {
        SymbolIterator it = symTable->getAllProgramSymbols(true);
        while (it.hasNext()) {
            Symbol* sym = it.next();
            if (!sym || sym->getName().empty()) continue;
            uint64_t off = static_cast<uint64_t>(sym->getAddress().getOffset());
            if (off == 0) continue;
            if (addrToName.find(off) == addrToName.end())
                addrToName[off] = sym->getName();
            if (nameToAddr.find(sym->getName()) == nameToAddr.end())
                nameToAddr[sym->getName()] = off;
        }
    }
}

// -----------------------------------------------------------------------
// Helper: build direct call-graph from instruction references stored
// in the Listing.
// NOTE: We iterate ALL instructions in the listing (not filtered by the
// AddressSetView) because the set passed to added() can have null-space
// addresses on some platforms, causing getInstructions(set) to return 0.
// -----------------------------------------------------------------------
static void buildCallGraph(
        Program* program,
        std::unordered_map<uint64_t, std::vector<uint64_t>>& callGraph) {

    auto* funcMgr = program->getFunctionManager();
    auto* listing = program->getListing();
    auto* refMgr = program->getReferenceManager();
    if (!funcMgr || !listing || !refMgr) return;

    // 1. Collect and sort all function entry points.
    // Filter out auto-generated func_start_* functions whose entry point
    // falls inside another function (created by FunctionStartAnalyzer
    // matching prologue patterns within real functions). These pollute the
    // call-graph mapping by stealing instructions from their parent.
    std::vector<uint64_t> entryPoints;
    std::unordered_map<uint64_t, std::string> epNames;
    FunctionIterator fit = funcMgr->getFunctions(true);
    while (fit.hasNext()) {
        Function* f = fit.next();
        if (f) {
            uint64_t ep = f->getEntryPoint().getOffset();
            std::string name = f->getName();
            entryPoints.push_back(ep);
            epNames[ep] = name;
        }
    }
    std::sort(entryPoints.begin(), entryPoints.end());
    // Remove func_start_* entries that overlap the previous function's
    // expected range (within 256 bytes of the preceding entry point).
    std::vector<uint64_t> filtered;
    for (size_t i = 0; i < entryPoints.size(); i++) {
        uint64_t ep = entryPoints[i];
        auto it = epNames.find(ep);
        bool isOverlap = false;
        if (it != epNames.end() && it->second.rfind("func_start_", 0) == 0) {
            if (i > 0 && ep - entryPoints[i - 1] < 256)
                isOverlap = true;
        }
        if (!isOverlap)
            filtered.push_back(ep);
    }
    entryPoints.swap(filtered);

    if (entryPoints.empty()) return;

    // 2. Iterate ALL instructions unconditionally (bypasses broken AddressSetView)
    std::vector<Instruction*> instructions = listing->getAllInstructions();

    for (Instruction* inst : instructions) {
        if (!inst) continue;
        Address instAddr = inst->getAddress();
        uint64_t offset = static_cast<uint64_t>(instAddr.getOffset());

        // Find the function entry point containing this instruction
        auto it = std::upper_bound(entryPoints.begin(), entryPoints.end(), offset);
        if (it == entryPoints.begin()) continue;
        --it;
        uint64_t callerOff = *it;

        // Get call references from this instruction
        std::vector<Reference*> refs = refMgr->getReferencesFrom(instAddr);
        for (Reference* ref : refs) {
            if (!ref) continue;
            const RefType* rt = ref->getReferenceType();
            if (rt && rt->isCall()) {
                Address toAddr = ref->getToAddress();
                uint64_t calleeOff = static_cast<uint64_t>(toAddr.getOffset());
                if (calleeOff != 0) {
                    callGraph[callerOff].push_back(calleeOff);
                }
            }
        }
    }
}

// -----------------------------------------------------------------------
// Helper: check if a name matches any known CRT prefix
// -----------------------------------------------------------------------
static bool matchesCrtPrefix(const std::string& name) {
    for (const char* const* p = kCrtPrefixes; *p; ++p) {
        if (name.rfind(*p, 0) == 0) return true;
    }
    return false;
}

// -----------------------------------------------------------------------
// Helper: is this a generic auto-generated name (sub_… or FUN_…)?
// -----------------------------------------------------------------------
static bool isAutoName(const std::string& n) {
    return n.empty()
        || n.rfind("sub_", 0) == 0
        || n.rfind("sub_0x", 0) == 0
        || n.rfind("FUN_", 0) == 0
        || n.rfind("function_0x", 0) == 0
        || n.rfind("func_start_", 0) == 0;
}

// -----------------------------------------------------------------------
// MainRecognitionAnalyzer
// -----------------------------------------------------------------------

MainRecognitionAnalyzer::MainRecognitionAnalyzer() = default;

bool MainRecognitionAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    auto* fm = program->getFunctionManager();
    int count = fm ? fm->getFunctionCount() : -1;
    return fm && count > 0;
}

bool MainRecognitionAnalyzer::added(Program* program,
                                    const AddressSetView& /*set*/,
                                    TaskMonitor* /*monitor*/,
                                    MessageLog& log) {
    if (!program) return false;

    auto* funcMgr  = program->getFunctionManager();
    auto* symTable = program->getSymbolTable();
    if (!funcMgr || !symTable) return true;

    // ----------------------------------------------------------------
    // 1. Build address<->name tables from the symbol table
    // ----------------------------------------------------------------
    std::unordered_map<uint64_t, std::string> addrToName;
    std::unordered_map<std::string, uint64_t> nameToAddr;
    buildSymbolMaps(program, addrToName, nameToAddr);

    // ----------------------------------------------------------------
    // 2. Build direct call-graph (caller → [callees])
    // ----------------------------------------------------------------
    std::unordered_map<uint64_t, std::vector<uint64_t>> callGraph;
    buildCallGraph(program, callGraph);

    if (callGraph.empty()) {
        // Nothing to analyse (maybe DisassemblyAnalyzer didn't run)
        log.append("MainRecognitionAnalyzer: call-graph is empty, skipping");
        return true;
    }

    // ----------------------------------------------------------------
    // 3. Find entry-point address
    // ----------------------------------------------------------------
    uint64_t entryPoint = 0;
    {
        auto it = nameToAddr.find("entry");
        if (it != nameToAddr.end()) entryPoint = it->second;
    }
    if (entryPoint == 0) {
        // Fallback: use the lowest-address function
        FunctionIterator fit = funcMgr->getFunctions(true);
        while (fit.hasNext()) {
            Function* f = fit.next();
            if (!f) continue;
            uint64_t off = static_cast<uint64_t>(f->getEntryPoint().getOffset());
            if (off > 0 && (entryPoint == 0 || off < entryPoint))
                entryPoint = off;
        }
    }

    // ----------------------------------------------------------------
    // 4. Classify functions as CRT by behavioural signature
    // ----------------------------------------------------------------
    static const std::string kThunkPrefix = "thunk_";

    auto classifyByBehavior = [&](uint64_t addr) -> std::pair<bool, std::string> {
        // First: check if this function's own name is a known CRT API
        auto selfNit = addrToName.find(addr);
        if (selfNit != addrToName.end()) {
            const std::string& selfName = selfNit->second;
            if (kCrtStartupApis.count(selfName))
                return {true, selfName};
            if (selfName.size() > kThunkPrefix.size() &&
                selfName.rfind(kThunkPrefix, 0) == 0) {
                std::string stripped = selfName.substr(kThunkPrefix.size());
                if (kCrtStartupApis.count(stripped))
                    return {true, stripped};
            }
        }
        // Then: check callees
        auto it = callGraph.find(addr);
        if (it == callGraph.end()) return {false, ""};
        for (uint64_t callee : it->second) {
            auto nit = addrToName.find(callee);
            if (nit == addrToName.end()) continue;
            const std::string& rawName = nit->second;
            if (kCrtStartupApis.count(rawName))
                return {true, rawName};
            if (rawName.size() > kThunkPrefix.size() &&
                rawName.rfind(kThunkPrefix, 0) == 0) {
                std::string stripped = rawName.substr(kThunkPrefix.size());
                if (kCrtStartupApis.count(stripped))
                    return {true, stripped};
            }
        }
        return {false, ""};
    };

    // Phase 1: seed
    std::unordered_set<uint64_t> classifiedCrt;

    // First: classify by behavior from call graph
    for (auto& kv : callGraph) {
        uint64_t addr = kv.first;
        auto [isCrt, reason] = classifyByBehavior(addr);
        if (isCrt) { classifiedCrt.insert(addr); continue; }

        // Name-based fallback
        auto nit = addrToName.find(addr);
        if (nit != addrToName.end()) {
            const std::string& name = nit->second;
            if (!name.empty() && name[0] == '_') { classifiedCrt.insert(addr); continue; }
            if (matchesCrtPrefix(name))           { classifiedCrt.insert(addr); continue; }
        }
    }

    // Second: also classify ALL functions with CRT names (even if not in call graph)
    for (auto& kv : addrToName) {
        uint64_t addr = kv.first;
        const std::string& name = kv.second;
        if (classifiedCrt.count(addr)) continue;
        if (kCrtStartupApis.count(name)) { classifiedCrt.insert(addr); continue; }
        if (!name.empty() && name[0] == '_') { classifiedCrt.insert(addr); continue; }
        if (matchesCrtPrefix(name))           { classifiedCrt.insert(addr); continue; }
    }

    // Phase 2: propagate
    std::deque<uint64_t> propQueue(classifiedCrt.begin(), classifiedCrt.end());
    std::unordered_set<uint64_t> propVisited;
    std::map<uint64_t, float> mainCandidates;

    // Build reverse call graph (callee → set of callers) for call-count heuristic
    std::unordered_map<uint64_t, std::unordered_set<uint64_t>> reverseCallGraph;
    for (auto& kv : callGraph) {
        for (uint64_t callee : kv.second) {
            reverseCallGraph[callee].insert(kv.first);
        }
    }

    while (!propQueue.empty()) {
        uint64_t addr = propQueue.front(); propQueue.pop_front();
        if (!propVisited.insert(addr).second) continue;

        auto it = callGraph.find(addr);
        if (it == callGraph.end()) continue;

        for (uint64_t callee : it->second) {
            if (callee == 0 || propVisited.count(callee)) continue;
            auto [isCrt, reason] = classifyByBehavior(callee);
            if (isCrt) {
                if (classifiedCrt.insert(callee).second)
                    propQueue.push_back(callee);
            } else if (classifiedCrt.count(addr)) {
                // Non-CRT callee of CRT = main candidate
                float conf = 0.70f;
                auto nit = addrToName.find(callee);
                bool anon = (nit == addrToName.end() || isAutoName(nit->second));
                if (anon) conf += 0.10f;
                // Bonus: callee does NOT itself call CRT (pure user code)
                auto cit = callGraph.find(callee);
                bool callsCrt = false;
                size_t calleeCount = 0;
                if (cit != callGraph.end()) {
                    calleeCount = cit->second.size();
                    for (uint64_t gc : cit->second) {
                        if (classifiedCrt.count(gc)) { callsCrt = true; break; }
                    }
                }
                if (!callsCrt) conf += 0.10f;
                // Call-count heuristic: main is called by very few callers
                auto rcit = reverseCallGraph.find(callee);
                size_t callerCount = (rcit != reverseCallGraph.end()) ? rcit->second.size() : 0;
                if (callerCount <= 1) conf += 0.15f;
                else if (callerCount <= 2) conf += 0.05f;
                if (callerCount > 4) conf -= 0.10f;
                // Callee count heuristic: main typically has 1-5 callees
                // Penalize functions with 0 callees (likely import thunks/data)
                if (calleeCount == 0) conf -= 0.15f;
                // Penalize functions with too many callees (likely CRT helpers)
                else if (calleeCount > 10) conf -= 0.10f;
                auto existing = mainCandidates.find(callee);
                if (existing == mainCandidates.end() || existing->second < conf)
                    mainCandidates[callee] = conf;
            }
        }
    }

    // Also process direct callees of entry that are CRT seeds.
    // For MinGW, __tmainCRTStartup calls main directly without calling
    // known CRT APIs, so we also classify entry callees as CRT when they
    // don't look like user-named code.
    if (entryPoint != 0) {
        auto eit = callGraph.find(entryPoint);
        if (eit != callGraph.end()) {
            for (uint64_t callee : eit->second) {
                if (callee == 0) continue;
                bool isCrt = false;
                auto [_isCrt, _reason] = classifyByBehavior(callee);
                if (_isCrt) {
                    isCrt = true;
                } else {
                    // Entry callees that are not user-named are CRT startup
                    auto nit = addrToName.find(callee);
                    bool userNamed = (nit != addrToName.end() && !isAutoName(nit->second));
                    if (!userNamed) isCrt = true;
                }
                if (isCrt && classifiedCrt.insert(callee).second)
                    propQueue.push_back(callee);
                else if (isCrt)
                    propQueue.push_back(callee);  // Already in classifiedCrt — still need to propagate
            }
            // Second propagation pass from newly seeded entry callees
            while (!propQueue.empty()) {
                uint64_t addr = propQueue.front(); propQueue.pop_front();
                if (!propVisited.insert(addr).second) continue;
                auto it = callGraph.find(addr);
                if (it == callGraph.end()) continue;
                for (uint64_t callee : it->second) {
                    if (callee == 0 || propVisited.count(callee)) continue;
                    auto [isCrt, reason] = classifyByBehavior(callee);
                    if (isCrt) {
                        if (classifiedCrt.insert(callee).second)
                            propQueue.push_back(callee);
                    } else if (classifiedCrt.count(addr)) {
                        float conf = 0.75f;
                        auto nit = addrToName.find(callee);
                        bool anon = (nit == addrToName.end() || isAutoName(nit->second));
                        if (anon) conf += 0.10f;
                        auto rcit = reverseCallGraph.find(callee);
                        size_t callerCount = (rcit != reverseCallGraph.end()) ? rcit->second.size() : 0;
                        if (callerCount <= 1) conf += 0.15f;
                        else if (callerCount <= 2) conf += 0.05f;
                        if (callerCount > 4) conf -= 0.10f;
                        auto existing = mainCandidates.find(callee);
                        if (existing == mainCandidates.end() || existing->second < conf)
                            mainCandidates[callee] = conf;
                    }
                }
            }
        }
    }

    // ----------------------------------------------------------------
    // 5. Select best candidate
    // ----------------------------------------------------------------
    if (mainCandidates.empty()) {
        Msg::info("MainRecognition", "no main() candidate found");
        log.append("MainRecognitionAnalyzer: no main() candidate found");
        return true;
    }

    uint64_t bestAddr = 0;
    float    bestConf = 0.0f;
    bool     wideChar = false;   // WinMain vs main

    for (auto& mc : mainCandidates) {
        uint64_t addr = mc.first;
        float    conf = mc.second;

        // Check if the parent CRT caller uses wide-char args → WinMain
        for (auto& crtAddr : classifiedCrt) {
            auto it = callGraph.find(crtAddr);
            if (it == callGraph.end()) continue;
            for (uint64_t callee : it->second) {
                if (callee == addr) {
                    // Does this CRT function call __wgetmainargs?
                    for (uint64_t gc : it->second) {
                        auto gn = addrToName.find(gc);
                        if (gn != addrToName.end() && gn->second == "__wgetmainargs") {
                            wideChar = true;
                        }
                    }
                }
            }
        }

        auto nit = addrToName.find(addr);
        bool anon = (nit == addrToName.end() || isAutoName(nit->second));
        float adjusted = conf + (anon ? 0.05f : 0.0f);
        // Tiebreaker: prefer addresses in executable memory (real code, not data)
        bool addrIsExec = false;
        if (program && program->getMemory()) {
            try {
                Address a(const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace()),
                          static_cast<int64_t>(addr));
                auto* block = program->getMemory()->getBlock(a);
                addrIsExec = (block && block->isExecute());
            } catch (...) {}
        }
        bool bestIsExec = false;
        if (bestAddr != 0 && program && program->getMemory()) {
            try {
                Address b(const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace()),
                          static_cast<int64_t>(bestAddr));
                auto* block = program->getMemory()->getBlock(b);
                bestIsExec = (block && block->isExecute());
            } catch (...) {}
        }
        if (adjusted > bestConf ||
            (adjusted == bestConf && addrIsExec && !bestIsExec) ||
            (adjusted == bestConf && addrIsExec == bestIsExec && addr > bestAddr)) {
            bestConf = adjusted; bestAddr = addr;
        }
    }

    if (bestAddr == 0) {
        Msg::info("MainRecognition", "best candidate address is 0, skipping");
        log.append("MainRecognitionAnalyzer: best candidate address is 0, skipping");
        return true;
    }

    // ----------------------------------------------------------------
    // 6. Rename the selected function
    // ----------------------------------------------------------------
    const std::string newName = wideChar ? "WinMain" : "main";

    Function* mainFunc = funcMgr->getFunctionAt(
        Address(const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace()),
                static_cast<int64_t>(bestAddr)));

    if (mainFunc) {
        std::string oldName = mainFunc->getName();
        mainFunc->setName(newName);
        // Update symbol table if a symbol exists at that address
        if (symTable) {
            auto* sym = symTable->getPrimarySymbol(mainFunc->getEntryPoint());
            if (sym) sym->setName(newName);
        }
        Msg::info("MainRecognition", "identified " + newName +
                  " at 0x" + std::to_string(bestAddr) +
                  " (old name: " + oldName + ")");
        log.append("MainRecognitionAnalyzer: identified " + newName +
                   " at 0x" + std::to_string(bestAddr) +
                   " (old name: " + oldName + ")");
    } else {
        Msg::info("MainRecognition", "candidate 0x" +
                  std::to_string(bestAddr) + " not in FunctionManager");
        log.append("MainRecognitionAnalyzer: candidate 0x" +
                   std::to_string(bestAddr) + " not in FunctionManager");
    }

    return true;
}

} // namespace ghidra
