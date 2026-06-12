        // === BEHAVIORAL CRT CLASSIFICATION ===
        // Classify functions by what they call, not by name.
        // Recovers main() in stripped binaries without PDBs or export names.
        //
        // Known CRT startup APIs — any function calling one of these is CRT,
        // regardless of its own (possibly anonymous) name.
        static const std::unordered_set<std::string> crtStartupApis = {
            "__getmainargs", "__wgetmainargs",
            "_initterm", "_initterm_e",
            "__set_app_type", "SetUnhandledExceptionFilter",
            "__scrt_initialize_crt", "__scrt_acquire_startup_lock",
            "__scrt_release_startup_lock",
            "exit", "atexit", "_cexit", "_c_exit",
            "__C_specific_handler", "_except_handler4_common",
            "_seh_filter_exe", "__scrt_is_user_crt_exception",
            "__scrt_unhandled_exception_filter",
            "_crt_atexit", "_register_thread_local_exe_atexit_callback",
            "_set_new_mode", "_set_new_handler",
            "__p___argc", "__p___argv", "__p___wargv", "__p___envp",
            "__p__acmdln", "__p__wcmdln",
            "__initenv", "get_initial_narrow_environment",
        };
        {
            // Build call graph from ALL decompiled functions.
            // This includes CRT functions that were decompiled but filtered
            // from output (still in symboltab via queryFunction).
            std::unordered_map<uint64_t, std::vector<uint64_t>> callGraph;
            std::unordered_set<uint64_t> allDecompiledAddrs;
            for (Funcdata* fd : allFds) {
                uint64_t callerOff = fd->getAddress().getOffset();
                if (callerOff == 0) continue;
                allDecompiledAddrs.insert(callerOff);
                for (int4 i = 0; i < fd->numCalls(); ++i) {
                    FuncCallSpecs* cs = fd->getCallSpecs(i);
                    uint64_t calleeOff = cs->getEntryAddress().getOffset();
                    if (calleeOff != 0)
                        callGraph[callerOff].push_back(calleeOff);
                }
            }
            for (const auto& pair : symbolNames) {
                uint64_t addr = pair.first;
                if (allDecompiledAddrs.count(addr)) continue;
                Address a(codeSpace, static_cast<int8>(addr));
                Funcdata* fd = arch->symboltab->getGlobalScope()->queryFunction(a);
                if (!fd || !fd->isProcStarted()) continue;
                allDecompiledAddrs.insert(addr);
                for (int4 i = 0; i < fd->numCalls(); ++i) {
                    FuncCallSpecs* cs = fd->getCallSpecs(i);
                    uint64_t calleeOff = cs->getEntryAddress().getOffset();
                    if (calleeOff != 0)
                        callGraph[addr].push_back(calleeOff);
                }
            }
            if (entryPoint != 0 && !allDecompiledAddrs.count(entryPoint)) {
                Address entryA(codeSpace, static_cast<int8>(entryPoint));
                Funcdata* entryFd = arch->symboltab->getGlobalScope()->queryFunction(entryA);
                if (entryFd) {
                    allDecompiledAddrs.insert(entryPoint);
                    for (int4 i = 0; i < entryFd->numCalls(); ++i) {
                        FuncCallSpecs* cs = entryFd->getCallSpecs(i);
                        uint64_t calleeOff = cs->getEntryAddress().getOffset();
                        if (calleeOff != 0)
                            callGraph[entryPoint].push_back(calleeOff);
                    }
                }
            }

            // Classify a function by behavioral signature:
            // does it call known CRT startup APIs?
            auto classifyByBehavior = [&](uint64_t addr)
                -> std::pair<bool, std::string> {
                auto calleesIt = callGraph.find(addr);
                if (calleesIt == callGraph.end())
                    return {false, ""};
                for (uint64_t callee : calleesIt->second) {
                    auto snIt = symbolNames.find(callee);
                    if (snIt != symbolNames.end()) {
                        const std::string& calleeName = snIt->second;
                        if (crtStartupApis.count(calleeName))
                            return {true, calleeName};
                    }
                }
                return {false, ""};
            };

            // Phase 1: Seed CRT classification.
            // Identify functions whose BEHAVIOR (callee imports) or name
            // marks them as CRT.
            std::unordered_set<uint64_t> crtSeeds;
            for (uint64_t addr : allDecompiledAddrs) {
                auto [isCrt, reason] = classifyByBehavior(addr);
                if (isCrt) {
                    crtSeeds.insert(addr);
                    if (std::getenv("ENIGMA_DEBUG")) {
                        auto snIt = symbolNames.find(addr);
                        std::cerr << "[CRT] 0x" << std::hex << addr
                                  << std::dec << " ("
                                  << (snIt != symbolNames.end()
                                      ? snIt->second : "?")
                                  << ") classified as CRT because it calls "
                                  << reason << "\n";
                    }
                    continue;
                }
                // Name-based fallback (secondary signal)
                if (!noCrt) {
                    auto snIt = symbolNames.find(addr);
                    if (snIt != symbolNames.end()) {
                        const std::string& name = snIt->second;
                        if (isPE && name[0] == '_') {
                            crtSeeds.insert(addr);
                            if (std::getenv("ENIGMA_DEBUG"))
                                std::cerr << "[CRT] 0x" << std::hex << addr
                                          << std::dec << " (" << name
                                          << ") classified as CRT because name starts with '_'\n";
                            continue;
                        }
                        for (const char* p : crtPrefixes) {
                            if (name.rfind(p, 0) == 0) {
                                crtSeeds.insert(addr);
                                if (std::getenv("ENIGMA_DEBUG"))
                                    std::cerr << "[CRT] 0x" << std::hex << addr
                                              << std::dec << " (" << name
                                              << ") classified as CRT because name matches prefix "
                                              << p << "\n";
                                break;
                            }
                        }
                    }
                }
            }

            // Phase 2: Propagate through call graph from CRT seeds.
            // CRT functions are internal nodes; non-CRT callees of CRT
            // functions are main candidates.
            std::unordered_set<uint64_t> classifiedCrt = crtSeeds;
            std::map<uint64_t, float> mainCandidates;
            std::deque<uint64_t> propQueue;
            std::unordered_set<uint64_t> propVisited;
            for (uint64_t seed : crtSeeds)
                propQueue.push_back(seed);
            while (!propQueue.empty()) {
                uint64_t addr = propQueue.front();
                propQueue.pop_front();
                if (!propVisited.insert(addr).second) continue;
                auto calleesIt = callGraph.find(addr);
                if (calleesIt == callGraph.end()) continue;
                for (uint64_t callee : calleesIt->second) {
                    if (callee == 0) continue;
                    if (propVisited.count(callee)) continue;
                    auto [isCrt, reason] = classifyByBehavior(callee);
                    if (isCrt) {
                        if (classifiedCrt.insert(callee).second) {
                            if (std::getenv("ENIGMA_DEBUG"))
                                std::cerr << "[CRT] 0x" << std::hex << callee
                                          << std::dec
                                          << " (propagated) classified as CRT because it calls "
                                          << reason << "\n";
                            propQueue.push_back(callee);
                        }
                    } else if (classifiedCrt.count(addr)) {
                        // Non-CRT callee of CRT = main candidate
                        float confidence = 0.7f;
                        auto calleeSnIt = symbolNames.find(callee);
                        bool isAnon = (calleeSnIt == symbolNames.end() ||
                            calleeSnIt->second.rfind("sub_0x", 0) == 0 ||
                            calleeSnIt->second.rfind("function_0x",0)==0);
                        if (isAnon) confidence += 0.1f;
                        auto calleeCalleesIt = callGraph.find(callee);
                        bool callsCrtIndirectly = false;
                        if (calleeCalleesIt != callGraph.end()) {
                            for (uint64_t gc : calleeCalleesIt->second) {
                                if (classifiedCrt.count(gc)) {
                                    callsCrtIndirectly = true;
                                    break;
                                }
                            }
                        }
                        if (!callsCrtIndirectly) confidence += 0.1f;
                        auto parentSnIt = symbolNames.find(addr);
                        if (parentSnIt != symbolNames.end()) {
                            auto parentCalleesIt = callGraph.find(addr);
                            if (parentCalleesIt != callGraph.end()) {
                                for (uint64_t pc : parentCalleesIt->second) {
                                    auto pcnIt = symbolNames.find(pc);
                                    if (pcnIt != symbolNames.end() &&
                                        (pcnIt->second == "__getmainargs" ||
                                         pcnIt->second == "__wgetmainargs")) {
                                        confidence += 0.1f;
                                        break;
                                    }
                                }
                            }
                        }
                        auto existing = mainCandidates.find(callee);
                        if (existing == mainCandidates.end() ||
                            existing->second < confidence)
                            mainCandidates[callee] = confidence;
                        if (std::getenv("ENIGMA_DEBUG"))
                            std::cerr << "[MAIN] Candidate discovered at 0x"
                                      << std::hex << callee << std::dec
                                      << "\n[MAIN] Confidence: " << confidence
                                      << "\n";
                    }
                }
            }

            // Entry's callees that are CRT seeds
            auto entryCalleesIt = callGraph.find(entryPoint);
            if (entryCalleesIt != callGraph.end() &&
                !classifiedCrt.count(entryPoint)) {
                for (uint64_t callee : entryCalleesIt->second) {
                    if (callee == 0) continue;
                    auto [isCrt, reason] = classifyByBehavior(callee);
                    if (isCrt &&
                        classifiedCrt.insert(callee).second) {
                        if (std::getenv("ENIGMA_DEBUG"))
                            std::cerr << "[CRT] 0x" << std::hex << callee
                                      << std::dec
                                      << " (entry callee) classified as CRT because it calls "
                                      << reason << "\n";
                        propQueue.push_back(callee);
                    }
                }
                while (!propQueue.empty()) {
                    uint64_t addr = propQueue.front();
                    propQueue.pop_front();
                    if (!propVisited.insert(addr).second) continue;
                    auto calleesIt = callGraph.find(addr);
                    if (calleesIt == callGraph.end()) continue;
                    for (uint64_t callee : calleesIt->second) {
                        if (callee == 0) continue;
                        if (propVisited.count(callee)) continue;
                        auto [isCrt, reason] =
                            classifyByBehavior(callee);
                        if (isCrt) {
                            if (classifiedCrt.insert(callee).second) {
                                if (std::getenv("ENIGMA_DEBUG"))
                                    std::cerr << "[CRT] 0x" << std::hex
                                              << callee << std::dec
                                              << " (entry-chain) classified as CRT because it calls "
                                              << reason << "\n";
                                propQueue.push_back(callee);
                            }
                        } else if (classifiedCrt.count(addr)) {
                            float confidence = 0.75f;
                            auto calleeSnIt =
                                symbolNames.find(callee);
                            bool isAnon = (calleeSnIt ==
                                symbolNames.end() ||
                                calleeSnIt->second.rfind(
                                    "sub_0x", 0) == 0);
                            if (isAnon) confidence += 0.1f;
                            auto existing =
                                mainCandidates.find(callee);
                            if (existing == mainCandidates.end() ||
                                existing->second < confidence)
                                mainCandidates[callee] = confidence;
                            if (std::getenv("ENIGMA_DEBUG"))
                                std::cerr << "[MAIN] Candidate at 0x"
                                          << std::hex << callee
                                          << std::dec
                                          << "\n[MAIN] Confidence: "
                                          << confidence << "\n";
                        }
                    }
                }
            }

            // Phase 3: Select best main candidate
            if (!mainCandidates.empty()) {
                uint64_t bestMainAddr = 0;
                float bestConf = 0.0f;
                for (auto& mc : mainCandidates) {
                    auto snIt = symbolNames.find(mc.first);
                    bool isAnon = (snIt == symbolNames.end() ||
                        snIt->second.rfind("sub_0x", 0) == 0 ||
                        snIt->second.rfind("function_0x",0) == 0);
                    float adjusted = mc.second +
                        (isAnon ? 0.1f : 0.0f);
                    if (adjusted > bestConf) {
                        bestConf = adjusted;
                        bestMainAddr = mc.first;
                    }
                }
                if (bestMainAddr != 0) {
                    symbolNames[bestMainAddr] = "main";
                    if (std::getenv("ENIGMA_DEBUG"))
                        std::cerr << "[MAIN] Selected 0x"
                                  << std::hex << bestMainAddr
                                  << std::dec << " -> main (confidence="
                                  << bestConf << ")\n";
                }
            }
        }
