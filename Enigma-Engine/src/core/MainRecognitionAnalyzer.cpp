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
#include <ghidra/NamingService.h>
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
// -----------------------------------------------------------------------
// Known CRT startup APIs — functions called by the CRT startup wrappers
// (mainCRTStartup, __tmainCRTStartup, WinMainCRTStartup, etc.).
// When a function calls one of these, it is part of the CRT startup
// chain.  Functions that call generic CRT runtime APIs (strlen, printf,
// malloc …) are NOT classified as startup — those are user functions
// using the standard library.
// -----------------------------------------------------------------------
static const std::unordered_set<std::string> kCrtStartupApis = {
    "__getmainargs",   "__wgetmainargs",
    "_initterm",       "_initterm_e",
    "__set_app_type",
    "SetUnhandledExceptionFilter",
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
    "_amsg_exit", "__iob_func", "__acrt_iob_func",
    "_beginthreadex", "_endthreadex",
    "__set_fmode", "__p__fmode", "__p__commode",
    "_configthreadlocale",
    "_callnewh", "__dllonexit", "_onexit", "__pxcptinfoptrs",
    "__CppXcptFilter", "_XcptFilter",
    "_except_handler2", "_except_handler3",
    "__crt_debugger_hook",
    "__setusermatherr", "_matherr",
    "__configure_narrow_argv", "__configure_wide_argv",
    "__initialize_narrow_environment", "__initialize_wide_environment",
    "IsDebuggerPresent",
    "EncodePointer", "DecodePointer",
    "__stdio_common_vfprintf",
    "InitializeCriticalSectionEx", "InitializeCriticalSectionAndSpinCount",
    "FlsAlloc", "FlsGetValue", "FlsSetValue", "FlsFree",
    "InitializeSRWLock", "AcquireSRWLockExclusive", "ReleaseSRWLockExclusive",
    "SleepConditionVariableSRW", "WakeConditionVariable",
};

// -----------------------------------------------------------------------
// CRT name prefixes used when behavioral analysis is unavailable
// -----------------------------------------------------------------------
// -----------------------------------------------------------------------
// Named imports that strongly indicate user code (not CRT startup).
// A function calling ANY of these gets a confidence bonus for main().
// Common CRT utility imports (malloc, memcpy, strlen, signal …) are
// intentionally excluded — both CRT and user code call them.
// -----------------------------------------------------------------------
static const std::unordered_set<std::string> kUserCodeImports = {
    // String comparison (password checkers, user logic)
    "strcmp", "strncmp", "wcscmp", "wcsncmp",
    "stricmp", "strnicmp", "strcasecmp", "strncasecmp",
    // Formatted I/O (user-facing output)
    "printf", "fprintf", "sprintf", "snprintf",
    "wprintf", "fwprintf", "swprintf",
    "_cprintf", "_cscanf",
    // User input
    "scanf", "fscanf", "sscanf",
    "gets", "fgets", "getchar",
    "puts", "fputs", "putchar",
    // File operations
    "fopen", "fclose", "freopen",
    "fread", "fwrite",
    "getc", "fgetc", "putc", "fputc",
    "ungetc",
    // String manipulation (user logic)
    "strcpy", "strncpy", "strcat", "strncat",
    "strstr", "strchr", "strrchr", "strtok",
    // Math (user computation)
    "rand", "srand", "time",
    // Console/terminal
    "system", "getenv",
    // Windows user interaction
    "MessageBoxA", "MessageBoxW",
    "MessageBoxExA", "MessageBoxExW",
};

static const char* const kCrtPrefixes[] = {
    "__scrt_", "__acrt_", "__vcrt_", "_crt",
    "msvcrt_", "_set_se_translator",
    "__mingw_", "__main", "__do_global_",
    "__security_", "_pei386_", "__chkstk",
    "__crt_", "__isa_", "__isa_available",
    "__rt_", "_callnewh", "__fpmath",
    "_except_handler", "_C_specific_handler",
    "_NLG_", "_configure_", "_initialize_",
    "_register_", "__image_base__",
    nullptr
};

// -----------------------------------------------------------------------
// Helper: build a name→address and address→name table from SymbolTable
// -----------------------------------------------------------------------
static void buildSymbolMaps(
        Program* program,
        std::unordered_map<uint64_t, std::string>& addrToName,
        std::unordered_map<std::string, uint64_t>& nameToAddr,
        std::map<uint64_t, std::string>& addrToNameSafe) {

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
                if (addrToName.find(off) == addrToName.end()) {
                    addrToName[off] = name;
                    addrToNameSafe[off] = name;
                }
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
            if (addrToName.find(off) == addrToName.end()) {
                addrToName[off] = sym->getName();
                addrToNameSafe[off] = sym->getName();
            }
            if (nameToAddr.find(sym->getName()) == nameToAddr.end()) {
                nameToAddr[sym->getName()] = off;
            }
            // Also index symbol name by address (for exact-name lookups).
            // Only add if different from the existing primary name.
            auto ait = addrToNameSafe.find(off);
            if (ait != addrToNameSafe.end() && ait->second != sym->getName()) {
                addrToNameSafe[off] = sym->getName();   // prefer symbol name
            }
        }
    }
}

// -----------------------------------------------------------------------
// Helper: build direct call-graph from instruction references stored
// in the Listing.
// NOTE: We iterate ALL instructions in the listing (not filtered by the
// AddressSetView) because the set passed to added() can have null-space
// addresses on some platforms, causing getInstructions(set) to return 0.
//
// Strategy:
//   • For each instruction, first try getFunctionContaining() which works
//     for functions whose bodies have been expanded past the 1-byte
//     placeholder. This correctly attributes instructions even when
//     FunctionStartAnalyzer has created synthetic func_0x* entries
//     overlapping real functions.
//   • If getFunctionContaining() returns null (the function body is still
//     the 1-byte placeholder), fall back to the nearest-entry-point proxy
//     using std::upper_bound over ALL function entry points (no name-based
//     filtering).  The old 256-byte / "func_0x" heuristic was removed
//     because it could silently drop legitimate functions and distort the
//     call graph.
// -----------------------------------------------------------------------
static void buildCallGraph(
        Program* program,
        std::unordered_map<uint64_t, std::vector<uint64_t>>& callGraph) {

    auto* funcMgr = program->getFunctionManager();
    auto* listing = program->getListing();
    auto* refMgr = program->getReferenceManager();
    if (!funcMgr || !listing || !refMgr) return;

    // 1. Collect and sort all function entry points (fallback attribution).
    std::vector<uint64_t> entryPoints;
    FunctionIterator fit = funcMgr->getFunctions(true);
    while (fit.hasNext()) {
        Function* f = fit.next();
        if (f) {
            entryPoints.push_back(f->getEntryPoint().getOffset());
        }
    }
    if (entryPoints.empty()) return;
    std::sort(entryPoints.begin(), entryPoints.end());

    // 2. Iterate ALL instructions unconditionally (bypasses broken AddressSetView)
    std::vector<Instruction*> instructions = listing->getAllInstructions();

    for (Instruction* inst : instructions) {
        if (!inst) continue;
        Address instAddr = inst->getAddress();
        uint64_t offset = static_cast<uint64_t>(instAddr.getOffset());

        // Find the function containing this instruction.
        // Preferred: getFunctionContaining() — works when function bodies
        // have been expanded past the 1-byte placeholder.
        uint64_t callerOff = 0;
        Function* containingFunc = funcMgr->getFunctionContaining(instAddr);
        if (containingFunc) {
            callerOff = static_cast<uint64_t>(containingFunc->getEntryPoint().getOffset());
        } else {
            // Fallback: nearest entry point <= instruction address.
            auto it = std::upper_bound(entryPoints.begin(), entryPoints.end(), offset);
            if (it == entryPoints.begin()) continue;
            --it;
            callerOff = *it;
        }

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
    return NamingService::isAutoGeneratedName(n);
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
    std::map<uint64_t, std::string> addrToNameSafe;
    buildSymbolMaps(program, addrToName, nameToAddr, addrToNameSafe);

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

    Msg::info("MainRecognition", "entry point at 0x" + std::to_string(entryPoint) +
              ", call graph has " + std::to_string(callGraph.size()) + " callers");
    Msg::info("MainRecognition", "after entry msg");
    Msg::info("MainRecognition", "phase 4 skipped");
    Msg::info("MainRecognition", "start simplified analysis");

    // Simplified analysis (bypasses GCC 16.1.0 unordered_map hang bug).
    // Copy callGraph data into plain containers.
    std::vector<uint64_t> crtGraphCallers;
    std::vector<std::vector<uint64_t>> crtGraphCallees;
    std::map<uint64_t, size_t> graphAddrToIndex;
    for (auto& kv : callGraph) {
        size_t idx = crtGraphCallers.size();
        crtGraphCallers.push_back(kv.first);
        crtGraphCallees.push_back(kv.second);
        graphAddrToIndex[kv.first] = idx;
    }

    std::map<uint64_t, float> mainCandidates;
    std::set<uint64_t> classifiedCrt;

    // Classify functions as CRT if:
    // 1. They have an underscore name (_*, __*), OR
    // 2. Any callee is a known CRT startup API (e.g. __getmainargs).
    const std::set<std::string> kCrtApiNames = {
        "__getmainargs", "__wgetmainargs", "_initterm", "_initterm_e",
        "main", "WinMain", "wmain", "wWinMain"
    };
    for (size_t ci = 0; ci < crtGraphCallers.size(); ++ci) {
        uint64_t addr = crtGraphCallers[ci];
        auto nit = addrToNameSafe.find(addr);
        if (nit != addrToNameSafe.end() && !nit->second.empty() && nit->second[0] == '_') {
            classifiedCrt.insert(addr);
            continue;
        }
        for (uint64_t callee : crtGraphCallees[ci]) {
            auto cn = addrToNameSafe.find(callee);
            if (cn == addrToNameSafe.end()) continue;
            if (kCrtApiNames.count(cn->second)) {
                classifiedCrt.insert(addr);
                break;
            }
        }
    }
    // Also classify underscore-named addrToNameSafe entries not in the graph
    for (auto& kv : addrToNameSafe) {
        if (!kv.second.empty() && kv.second[0] == '_')
            classifiedCrt.insert(kv.first);
    }
    // Find direct callees of entry point as main candidates.
    if (entryPoint != 0) {
        auto eit = graphAddrToIndex.find(entryPoint);
        if (eit != graphAddrToIndex.end()) {
            for (uint64_t callee : crtGraphCallees[eit->second]) {
                if (callee == 0 || classifiedCrt.count(callee)) continue;
                float conf = 0.80f;
                auto nit = addrToNameSafe.find(callee);
                bool anon = (nit == addrToNameSafe.end() || isAutoName(nit->second));
                if (anon) conf += 0.10f;
                mainCandidates[callee] = conf;
            }
        }
    }

    // Also check non-CRT callees of other CRT functions.
    for (size_t ci = 0; ci < crtGraphCallers.size(); ++ci) {
        if (!classifiedCrt.count(crtGraphCallers[ci])) continue;
        for (uint64_t callee : crtGraphCallees[ci]) {
            if (callee == 0 || classifiedCrt.count(callee)) continue;
            if (mainCandidates.count(callee)) continue;
            float conf = 0.70f;
            mainCandidates[callee] = conf;
        }
    }

    if (mainCandidates.empty()) {
        Msg::info("MainRecognition", "no main() candidate found (simplified)");
        log.append("MainRecognitionAnalyzer: no main() candidate found (simplified)");
        return true;
    }

    // ----------------------------------------------------------------
    // 5. Select best candidate
    // ----------------------------------------------------------------

    // Find addresses of exactly-named "main", "WinMain", "wmain" in addrToNameSafe.
    uint64_t exactMainAddr = 0, exactWinMainAddr = 0, exactWmainAddr = 0;
    for (auto& kv : addrToNameSafe) {
        if (kv.second == "main")       exactMainAddr = kv.first;
        if (kv.second == "WinMain")    exactWinMainAddr = kv.first;
        if (kv.second == "wmain")      exactWmainAddr = kv.first;
    }

    uint64_t bestAddr = 0;
    float    bestConf = 0.0f;
    bool     wideChar = false;   // WinMain vs main

    for (auto& mc : mainCandidates) {
        uint64_t addr = mc.first;
        float    conf = mc.second;

        // Check if the parent CRT caller uses wide-char args → WinMain
        for (auto& crtAddr : classifiedCrt) {
            auto crtIdxIt = graphAddrToIndex.find(crtAddr);
            if (crtIdxIt == graphAddrToIndex.end()) continue;
            const auto& crtCallees = crtGraphCallees[crtIdxIt->second];
            for (uint64_t callee : crtCallees) {
                if (callee == addr) {
                    for (uint64_t gc : crtCallees) {
                        auto gn = addrToNameSafe.find(gc);
                        if (gn != addrToNameSafe.end() && gn->second == "__wgetmainargs") {
                            wideChar = true;
                        }
                    }
                }
            }
        }

        auto nit = addrToNameSafe.find(addr);
        bool anon = (nit == addrToNameSafe.end() || isAutoName(nit->second));
        float adjusted = conf + (anon ? 0.05f : 0.0f);
        // Boost if address matches known main symbol
        if (addr == exactMainAddr)    adjusted += 0.30f;
        if (addr == exactWinMainAddr) adjusted += 0.25f;
        if (addr == exactWmainAddr)   adjusted += 0.25f;
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
            (adjusted == bestConf && addrIsExec == bestIsExec && addr < bestAddr)) {
            bestConf = adjusted; bestAddr = addr;
        }
    }

    if (bestAddr == 0) {
        Msg::info("MainRecognition", "best candidate address is 0, skipping");
        log.append("MainRecognitionAnalyzer: best candidate address is 0, skipping");
        return true;
    }

    {
        auto nit = addrToNameSafe.find(bestAddr);
        std::string bestName = (nit != addrToNameSafe.end()) ? nit->second : "(unnamed)";
        Msg::info("MainRecognition", "selected candidate 0x" +
                  std::to_string(bestAddr) + " [" + bestName + "] confidence=" +
                  std::to_string(bestConf) + " wide=" + (wideChar ? "yes" : "no"));
    }

    // ----------------------------------------------------------------
    // 6. Rename the selected function
    // ----------------------------------------------------------------
    const std::string newName = wideChar ? "WinMain" : "main";

    Function* mainFunc = funcMgr->getFunctionAt(
        Address(const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace()),
                static_cast<int64_t>(bestAddr)));

    NamingService naming(program);

    if (mainFunc) {
        std::string oldName = mainFunc->getName();
        if (isAutoName(oldName)) {
            auto result = naming.assignName(mainFunc, newName, SourceType::ANALYSIS);
            if (result.success) {
                naming.assignAlias(bestAddr, newName, SourceType::ANALYSIS);
                Msg::info("MainRecognition", "identified " + newName +
                          " at 0x" + std::to_string(bestAddr) +
                          " (old name: " + oldName + ")");
                log.append("MainRecognitionAnalyzer: identified " + newName +
                           " at 0x" + std::to_string(bestAddr) +
                           " (old name: " + oldName + ")");
            } else if (result.blocked) {
                Msg::info("MainRecognition", "rename blocked: " + result.reason);
            }
        } else {
            Msg::info("MainRecognition", "candidate " + newName +
                      " at 0x" + std::to_string(bestAddr) +
                      " skipped — already named '" + oldName + "'");
        }
    } else {
        Msg::info("MainRecognition", "candidate 0x" +
                  std::to_string(bestAddr) + " not in FunctionManager");
        log.append("MainRecognitionAnalyzer: candidate 0x" +
                   std::to_string(bestAddr) + " not in FunctionManager");
    }

    // ----------------------------------------------------------------
    // 7. MinGW CRT wrapper naming (transitive import thunk resolution)
    //    Runs after ImportThunkAnalyzer has named all import thunks.
    //    Only names functions that are direct callees of the user's
    //    main() to avoid over-naming internal CRT helpers.
    // ----------------------------------------------------------------
    {
        // Build the set of direct callees of main
        std::set<uint64_t> mainDirectCallees;
        auto mainCgIdxIt = graphAddrToIndex.find(bestAddr);
        if (mainCgIdxIt != graphAddrToIndex.end()) {
            for (uint64_t callee : crtGraphCallees[mainCgIdxIt->second]) {
                mainDirectCallees.insert(callee);
            }
        }
        if (mainDirectCallees.empty()) goto skipMingwStep;

        // Collect all import thunks: named functions with isThunk() == true.
        std::set<uint64_t> importThunkAddresses;
        std::unordered_map<uint64_t, std::string> thunkNameMap;
        FunctionIterator fitAll = funcMgr->getFunctions(true);
        while (fitAll.hasNext()) {
            Function* f = fitAll.next();
            if (f && f->isThunk()) {
                uint64_t addr = f->getEntryPoint().getOffset();
                importThunkAddresses.insert(addr);
                thunkNameMap[addr] = f->getName();
            }
        }

        if (!importThunkAddresses.empty()) {
            AddressSpace* defaultSpace = const_cast<AddressSpace*>(
                program->getAddressFactory()->getDefaultAddressSpace());

            int mingwNamed = 0;
            NamingService naming(program);

            // Only process direct callees of main that are still unnamed
            for (uint64_t calleeAddr : mainDirectCallees) {
                Function* f = funcMgr->getFunctionAt(
                    Address(defaultSpace, static_cast<int64_t>(calleeAddr)));
                if (!f) continue;
                std::string cn = f->getName();
                if (!isAutoName(cn)) continue;

                // BFS up to depth 6 to find reachable import thunks
                std::set<uint64_t> reachable;
                std::set<uint64_t> visited;
                std::vector<std::pair<uint64_t, int>> queue;
                queue.push_back({calleeAddr, 0});
                visited.insert(calleeAddr);
                size_t head = 0;
                while (head < queue.size()) {
                    auto [curAddr, depth] = queue[head++];
                    if (depth >= 6) continue;
                    auto bfsIdxIt = graphAddrToIndex.find(curAddr);
                    if (bfsIdxIt == graphAddrToIndex.end()) continue;
                    for (uint64_t callee : crtGraphCallees[bfsIdxIt->second]) {
                        if (importThunkAddresses.count(callee)) {
                            reachable.insert(callee);
                        } else if (visited.insert(callee).second) {
                            Function* calleeFunc = funcMgr->getFunctionAt(
                                Address(defaultSpace, static_cast<int64_t>(callee)));
                            if (calleeFunc && isAutoName(calleeFunc->getName())) {
                                queue.push_back({callee, depth + 1});
                            }
                        }
                    }
                }

                if (reachable.empty()) continue;

                // Check reachable import thunks against known MinGW patterns
                for (uint64_t t : reachable) {
                    auto it = thunkNameMap.find(t);
                    if (it == thunkNameMap.end()) continue;
                    const std::string& importName = it->second;

                    // __mingw_printf: wraps character-level output
                    if (importName == "vfprintf" || importName == "fprintf" ||
                        importName == "fputc") {
                        auto result = naming.assignName(f, "__mingw_printf", SourceType::ANALYSIS);
                        if (result.success) {
                            naming.assignAlias(calleeAddr, "__mingw_printf", SourceType::ANALYSIS);
                            ++mingwNamed;
                            Msg::info("MainRecognition", "named 0x" +
                                      std::to_string(calleeAddr) + " " + cn +
                                      " -> __mingw_printf");
                        }
                        break;
                    }

                    // __mingw_scanf: wraps character-level input
                    if (importName == "vfscanf" || importName == "fscanf" ||
                        importName == "getc" || importName == "fgetc" ||
                        importName == "ungetc") {
                        auto result = naming.assignName(f, "__mingw_scanf", SourceType::ANALYSIS);
                        if (result.success) {
                            naming.assignAlias(calleeAddr, "__mingw_scanf", SourceType::ANALYSIS);
                            ++mingwNamed;
                            Msg::info("MainRecognition", "named 0x" +
                                      std::to_string(calleeAddr) + " " + cn +
                                      " -> __mingw_scanf");
                        }
                        break;
                    }
                }
            }

            if (mingwNamed > 0) {
                Msg::info("MainRecognition",
                          "MinGW CRT: named " + std::to_string(mingwNamed) +
                          " wrapper functions via transitive import thunk resolution");
                log.append("MainRecognitionAnalyzer: MinGW CRT: named " +
                           std::to_string(mingwNamed) +
                           " wrapper functions via transitive import thunk resolution");
            }
        }
    }
skipMingwStep:;

    return true;
}

} // namespace ghidra
