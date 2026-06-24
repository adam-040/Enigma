#include <ghidra/FidAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/ProgramAddressFactory.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/Reference.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/FunctionIterator.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/Symbol.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/Msg.h>
#include <ghidra/FidHasher.h>
#include <ghidra/KnownFunctionHashes.h>
#include <cstdint>
#include <vector>
#include <string>
#include <unordered_map>
#include <set>
#include <algorithm>

namespace ghidra {

static bool isAutoGenName(const std::string& name) {
    return name.rfind("FUN_", 0) == 0 ||
           name.rfind("sub_", 0) == 0 ||
           name.rfind("func_start_", 0) == 0 ||
           name.rfind("func_call_", 0) == 0 ||
           name.rfind("func_jmp_", 0) == 0 ||
           name.rfind("func_rva_", 0) == 0 ||
           name.rfind("func_data_", 0) == 0 ||
           name.rfind("func_fallback_", 0) == 0;
}

FidAnalyzer::FidAnalyzer()
    : AbstractAnalyzer("Function ID",
                       "Names CRT startup and helper functions by tracing call chains from the entry point and checking references to named import thunks.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FUNCTION_ID_ANALYSIS);
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

bool FidAnalyzer::canAnalyze(Program* program) const {
    return program != nullptr;
}

bool FidAnalyzer::added(Program* program, const AddressSetView& set,
                         TaskMonitor* monitor, MessageLog& log) {
    if (!program || !monitor) return true;
    monitor->setMessage("Identifying library functions via call-chain analysis...");

    FunctionManager* funcMgr = program->getFunctionManager();
    SymbolTable* symTable = program->getSymbolTable();
    Listing* listing = program->getListing();
    ReferenceManager* refMgr = program->getReferenceManager();
    Memory* memory = program->getMemory();
    AddressSpace* defaultSpace = const_cast<AddressSpace*>(
        program->getAddressFactory()->getDefaultAddressSpace());
    if (!funcMgr || !symTable || !listing || !refMgr) return true;

    // Cache all functions in sorted order once, reuse across all steps.
    FunctionIterator fitAll = funcMgr->getFunctions(true);
    std::vector<Function*> allFunctions;
    while (fitAll.hasNext()) {
        Function* f = fitAll.next();
        if (f) allFunctions.push_back(f);
    }
    if (allFunctions.empty()) return true;

    int identified = 0;

    // Rename helper — O(1) lookup via getFunctionAt instead of linear scan.
    auto tryRename = [&](uint64_t off, const std::string& newName) -> bool {
        if (off == 0) return false;
        Address addr(defaultSpace, static_cast<int64_t>(off));
        Function* func = funcMgr->getFunctionAt(addr);
        if (!func) return false;

        std::string cur = func->getName();
        if (!cur.empty() && !isAutoGenName(cur)) {
            if (cur != "entry" && cur != "main") return false;
        }
        if (!symTable->hasSymbol(addr) ||
            symTable->getPrimarySymbol(addr) == nullptr) {
            symTable->createLabel(addr, newName, SourceType::ANALYSIS);
        } else {
            Symbol* ps = symTable->getPrimarySymbol(addr);
            if (isAutoGenName(ps->getName())) {
                symTable->createLabel(addr, newName, SourceType::ANALYSIS);
            }
        }
        if (cur != "entry" && cur != "main") {
            func->setName(newName);
        }
        return true;
    };

    // Step 0: Hash-based function identification (FLIRT-like byte pattern matching)
    {
        FidHasher hasher;
        KnownFunctionHashes knownHashes;
        for (Function* f : allFunctions) {
            std::string cn = f->getName();
            if (!isAutoGenName(cn)) continue;

            FidHashQuad hq = hasher.hashFunction(f, program);
            if (hq.fullHash == 0) continue;

            const char* matchedName = knownHashes.lookup(hq.fullHash, hq.totalBytes);
            if (matchedName) {
                uint64_t a = f->getEntryPoint().getOffset();
                if (tryRename(a, matchedName)) ++identified;
            }
        }
    }

    // Step 1: Build call + reverse call graph from references
    std::unordered_map<uint64_t, std::vector<uint64_t>> callGraph;
    std::unordered_map<uint64_t, std::vector<uint64_t>> reverseCallGraph;
    std::set<uint64_t> entryPoints;

    for (Function* f : allFunctions) {
        entryPoints.insert(f->getEntryPoint().getOffset());
    }

    // Iterate all references instead of all instructions + per-instr ref lookup.
    // Eliminates 1.27M getAllInstructions copy + 1.27M getReferencesFrom(toString()) calls.
    std::vector<Reference*> allRefs = refMgr->getAllReferences();
    for (Reference* ref : allRefs) {
        if (!ref) continue;
        const RefType* rt = ref->getReferenceType();
        if (!rt || !rt->isCall()) continue;

        uint64_t callee = ref->getToAddress().getOffset();
        if (callee == 0) continue;

        uint64_t fromAddr = ref->getFromAddress().getOffset();
        auto it = entryPoints.upper_bound(fromAddr);
        if (it == entryPoints.begin()) continue;
        --it;
        uint64_t caller = *it;

        callGraph[caller].push_back(callee);
        reverseCallGraph[callee].push_back(caller);
    }

    // Helper lambdas using reverse call graph
    auto callsTarget = [&](uint64_t addr, uint64_t target) -> bool {
        auto it = callGraph.find(addr);
        if (it == callGraph.end()) return false;
        for (uint64_t c : it->second) if (c == target) return true;
        return false;
    };
    auto callsAny = [&](uint64_t addr, const std::set<uint64_t>& targets) -> bool {
        auto it = callGraph.find(addr);
        if (it == callGraph.end()) return false;
        for (uint64_t c : it->second) if (targets.count(c)) return true;
        return false;
    };
    auto countCalls = [&](uint64_t addr, const std::set<uint64_t>& targets) -> int {
        auto it = callGraph.find(addr);
        if (it == callGraph.end()) return 0;
        int cnt = 0;
        for (uint64_t c : it->second) if (targets.count(c)) ++cnt;
        return cnt;
    };

    // Step 2: Find known addresses from symbol table + function names
    uint64_t entryAddr = 0;
    uint64_t mainAddr = 0;
    std::set<uint64_t> inittermThunks;
    std::set<uint64_t> setAppTypeThunks;
    std::set<uint64_t> securityTimeThunks;
    bool hasGuiImports = false;

    SymbolIterator symIt = symTable->getAllProgramSymbols(true);
    while (symIt.hasNext()) {
        Symbol* sym = symIt.next();
        if (!sym) continue;
        std::string n = sym->getName();
        uint64_t a = sym->getAddress().getOffset();
        if (a == 0) continue;
        if (n == "entry") entryAddr = a;
        if (n == "main") mainAddr = a;
        if (n == "thunk_RegisterClassW" || n == "thunk_RegisterClassA" ||
            n == "thunk_CreateWindowExW" || n == "thunk_CreateWindowExA" ||
            n == "thunk_ShowWindow" || n == "thunk_DialogBoxParamW" ||
            n == "thunk_DefWindowProcW" || n == "thunk_DispatchMessageW" ||
            n == "thunk_TranslateMessage" || n == "thunk_GetMessageW" ||
            n == "DelayLoad_RegisterClassW" || n == "DelayLoad_RegisterClassA" ||
            n == "DelayLoad_CreateWindowExW" || n == "DelayLoad_CreateWindowExA" ||
            n == "DelayLoad_ShowWindow" || n == "DelayLoad_DialogBoxParamW" ||
            n == "DelayLoad_DefWindowProcW" || n == "DelayLoad_DispatchMessageW" ||
            n == "DelayLoad_TranslateMessage" || n == "DelayLoad_GetMessageW" ||
            n == "DelayLoad_ShellExecuteW") hasGuiImports = true;
        if (n.rfind("thunk__initterm", 0) == 0)
            inittermThunks.insert(a);
        if (n.rfind("thunk__set_app_type", 0) == 0)
            setAppTypeThunks.insert(a);
        if (n == "thunk_GetSystemTimeAsFileTime" || n == "thunk_QueryPerformanceCounter" ||
            n == "thunk_GetCurrentProcessId" || n == "thunk_GetCurrentThreadId")
            securityTimeThunks.insert(a);
    }

    // Also scan function names for thunks (uses cached allFunctions)
    for (Function* f : allFunctions) {
        std::string n = f->getName();
        uint64_t a = f->getEntryPoint().getOffset();
        if (a == 0) continue;
        if (n == "entry") entryAddr = a;
        if (n == "main") mainAddr = a;
        if (n.rfind("thunk__initterm", 0) == 0 && !inittermThunks.count(a))
            inittermThunks.insert(a);
        if (n.rfind("thunk__set_app_type", 0) == 0 && !setAppTypeThunks.count(a))
            setAppTypeThunks.insert(a);
    }

    // Step 3: Name the entry function
    if (entryAddr > 0) {
        for (Function* f : allFunctions) {
            if (f->getEntryPoint().getOffset() != entryAddr) continue;
            std::string cn = f->getName();
            if (cn.rfind("FUN_", 0) == 0 || cn.rfind("sub_", 0) == 0 ||
                cn.rfind("func_start_", 0) == 0) {
                std::string startupName = hasGuiImports ? "WinMainCRTStartup" : "mainCRTStartup";
                if (tryRename(entryAddr, startupName)) ++identified;
            }
        }
    }

    uint64_t sehAddr = 0;

    // Step 4: Find __scrt_common_main_seh
    {
        for (Function* f : allFunctions) {
            uint64_t a = f->getEntryPoint().getOffset();
            if (a == entryAddr || a == mainAddr) continue;
            std::string cn = f->getName();
            if (!isAutoGenName(cn)) continue;

            bool callsInit = countCalls(a, inittermThunks) >= 1;
            bool callsApp = countCalls(a, setAppTypeThunks) >= 1;
            if (callsInit || callsApp) {
                if (tryRename(a, "__scrt_common_main_seh")) {
                    ++identified;
                    sehAddr = a;
                    break;
                }
            }
        }

        // Step 5: Find invoke_main — called from __scrt_common_main_seh, calls main
        if (sehAddr > 0) {
            uint64_t invAddr = 0;
            auto sehIt = callGraph.find(sehAddr);
            if (sehIt != callGraph.end()) {
                for (uint64_t sehCallee : sehIt->second) {
                    if (sehCallee == entryAddr || sehCallee == sehAddr) continue;
                    if (mainAddr > 0 && callsTarget(sehCallee, mainAddr)) {
                        if (tryRename(sehCallee, "invoke_main")) {
                            ++identified; invAddr = sehCallee; break;
                        }
                    }
                }
            }
            if (invAddr == 0 && mainAddr > 0) {
                for (Function* f : allFunctions) {
                    uint64_t a = f->getEntryPoint().getOffset();
                    if (a == entryAddr || a == mainAddr) continue;
                    std::string cn = f->getName();
                    if (!isAutoGenName(cn)) continue;
                    if (callsTarget(a, mainAddr)) {
                        if (tryRename(a, "invoke_main")) {
                            ++identified; break;
                        }
                    }
                }
            }
        }
    }

    // Step 5 (duplicate): Search all functions that call main
    if (mainAddr > 0) {
        for (Function* f : allFunctions) {
            uint64_t a = f->getEntryPoint().getOffset();
            if (a == entryAddr || a == mainAddr) continue;
            if (callsTarget(a, mainAddr)) {
                std::string cn = f->getName();
                if (isAutoGenName(cn)) {
                    if (tryRename(a, "invoke_main")) { ++identified; break; }
                }
            }
        }
    }

    // Step 6: __security_init_cookie
    if (!securityTimeThunks.empty()) {
        for (Function* f : allFunctions) {
            uint64_t a = f->getEntryPoint().getOffset();
            if (a == entryAddr || a == mainAddr) continue;
            if (callsAny(a, securityTimeThunks)) {
                std::string cn = f->getName();
                if (isAutoGenName(cn)) {
                    if (tryRename(a, "__security_init_cookie")) ++identified;
                }
            }
        }
    }

    // Step 7: __security_check_cookie
    {
        for (Function* f : allFunctions) {
            uint64_t a = f->getEntryPoint().getOffset();
            if (a == entryAddr || a == mainAddr) continue;
            uint64_t nCallers = static_cast<uint64_t>(reverseCallGraph[a].size());
            if (nCallers < 5) continue;

            std::string cn = f->getName();
            if (!isAutoGenName(cn)) continue;

            MemoryBlock* block = memory ? memory->getBlock(f->getEntryPoint()) : nullptr;
            if (!block || !block->isInitialized() || !block->isExecute()) continue;

            uint8_t buf[16];
            int r = block->getBytes(f->getEntryPoint(), buf, 16);
            if (r < 8) continue;

            bool hasCookie = false;
            for (int i = 0; i <= r - 3; ++i) {
                if ((buf[i] == 0x48 && buf[i+1] == 0x33 && buf[i+2] == 0x0D) ||
                    (buf[i] == 0x48 && buf[i+1] == 0x3B && buf[i+2] == 0x0D)) {
                    hasCookie = true; break;
                }
            }
            if (hasCookie && tryRename(a, "__security_check_cookie")) ++identified;
        }
    }

    // Step 8: _guard_check_icall and _guard_dispatch_icall
    {
        for (Function* f : allFunctions) {
            uint64_t a = f->getEntryPoint().getOffset();
            std::string cn = f->getName();
            if (!isAutoGenName(cn)) continue;

            MemoryBlock* block = memory ? memory->getBlock(f->getEntryPoint()) : nullptr;
            if (!block || !block->isInitialized() || !block->isExecute()) continue;

            uint8_t buf[8];
            int r = block->getBytes(f->getEntryPoint(), buf, 8);
            if (r < 3) continue;

            if (r >= 3 && buf[0] == 0xC2 && buf[1] == 0x00 && buf[2] == 0x00) {
                if (tryRename(a, "_guard_check_icall")) ++identified;
                continue;
            }

            if (r >= 2 && buf[0] == 0xFF && buf[1] == 0xE0) {
                if (tryRename(a, "_guard_dispatch_icall")) ++identified;
                continue;
            }
        }
    }

    if (identified > 0)
        Msg::info(getName(), "Identified " + std::to_string(identified) +
                  " CRT/library functions via call-chain analysis.");
    return true;
}

} // namespace ghidra
