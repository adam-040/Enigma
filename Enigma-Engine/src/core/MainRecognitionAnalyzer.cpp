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

    Msg::info("MainRecognition", "entry point at 0x" + std::to_string(entryPoint) +
              ", call graph has " + std::to_string(callGraph.size()) + " callers");

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

    Msg::info("MainRecognition",
              std::to_string(classifiedCrt.size()) + " CRT-classified functions seeded");

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
                int  callsNamedImport = 0;  // ← count, not bool
                if (cit != callGraph.end()) {
                    calleeCount = cit->second.size();
                    for (uint64_t gc : cit->second) {
                        if (classifiedCrt.count(gc)) { callsCrt = true; break; }
                        // Named non-CRT import → user-code indicator
                        auto gnit = addrToName.find(gc);
                        if (gnit != addrToName.end() && !isAutoName(gnit->second)) {
                            if (kUserCodeImports.count(gnit->second))
                                ++callsNamedImport;
                        }
                    }
                }
                if (!callsCrt) conf += 0.10f;
                // Bonus for calling a named non-startup import (strcmp,
                // printf, fopen …).  Most CRT internal helpers call 0
                // named imports — only actual user code uses these APIs.
                if (callsNamedImport >= 1) conf += 0.25f;
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
    // known CRT APIs, so we need to classify entry callees as CRT when
    // they are reachable from the CRT graph (without assuming ALL unnamed
    // entry callees are CRT — that would misclassify user main() when
    // the entry calls it directly with no CRT startup).
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
                    // Entry callee was not classified by behavior alone.
                    // Check if it calls any function that IS already
                    // classified as CRT — if so, it is part of the CRT
                    // startup chain (e.g. __mingw_CRTStartup → _main
                    // where _main is classified by underscore name).
                    // This avoids the old "all unnamed entry callees
                    // are CRT" heuristic that misclassifies user main()
                    // when the entry calls it directly (no CRT startup).
                    auto cit = callGraph.find(callee);
                    if (cit != callGraph.end()) {
                        for (uint64_t gcallee : cit->second) {
                            if (classifiedCrt.count(gcallee)) {
                                isCrt = true;
                                break;
                            }
                        }
                    }
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
                        // User-code indicator: callee calls ≥2 named non-CRT imports
                        auto cit2 = callGraph.find(callee);
                        int callsNamedImport2 = 0;
                        if (cit2 != callGraph.end()) {
                            for (uint64_t gc : cit2->second) {
                                auto gnit = addrToName.find(gc);
                                if (gnit != addrToName.end() && !isAutoName(gnit->second)) {
                                    if (kUserCodeImports.count(gnit->second))
                                        { if (++callsNamedImport2 >= 2) break; }
                                }
                            }
                        }
                        if (callsNamedImport2 >= 1) conf += 0.25f;
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
        Msg::info("MainRecognition", "no main() candidate found (" +
                  std::to_string(classifiedCrt.size()) + " CRT functions, " +
                  std::to_string(callGraph.size()) + " callers in graph)");
        log.append("MainRecognitionAnalyzer: no main() candidate found");
        return true;
    }

    {
        std::string candMsg = "main candidates:";
        for (auto& mc : mainCandidates) {
            auto nit = addrToName.find(mc.first);
            std::string name = (nit != addrToName.end()) ? nit->second : "(unnamed)";
            candMsg += " 0x" + std::to_string(mc.first) + "[" + name + "]=" +
                       std::to_string(mc.second);
        }
        Msg::info("MainRecognition", candMsg);
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

    {
        auto nit = addrToName.find(bestAddr);
        std::string bestName = (nit != addrToName.end()) ? nit->second : "(unnamed)";
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
        auto mainCgIt = callGraph.find(bestAddr);
        if (mainCgIt != callGraph.end()) {
            for (uint64_t callee : mainCgIt->second) {
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
                    auto cgIt = callGraph.find(curAddr);
                    if (cgIt == callGraph.end()) continue;
                    for (uint64_t callee : cgIt->second) {
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
