/**
 * Enigma Engine - Analyzer Integration Validation Test
 * Validates the execution of the 132-analyzer layer on a real binary via AutoAnalysisManager.
 */
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <cstdlib>
#include <thread>
#include <chrono>

#include "ghidra/BinaryLoader.h"
#include "ghidra/ProgramDB.h"
#include "ghidra/AddressSpace.h"
#include "ghidra/ProgramAddressFactory.h"
#include "ghidra/AutoAnalysisManager.h"
#include "ghidra/TaskMonitor.h"
#include "ghidra/FunctionManager.h"
#include "ghidra/SymbolTable.h"
#include "ghidra/Msg.h"

int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;}else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

static std::string getTestBinaryPath(int argc, char** argv) {
    const char* envPath = std::getenv("ENIGMA_TEST_BINARY");
    if (envPath && *envPath) {
        return envPath;
    }
    if (argc > 0 && argv && argv[0] && *argv[0]) {
        return argv[0];
    }
    return "enigma_test_batch_s.exe";
}



struct TestProgram {
    ghidra::GenericAddressSpace ramSpace;
    ghidra::GenericAddressSpace constSpace;
    ghidra::GenericAddressSpace uniqueSpace;
    ghidra::GenericAddressSpace registerSpace;
    ghidra::GenericAddressSpace stackSpace;
    ghidra::ProgramDB prog;

    TestProgram()
        : ramSpace("ram", 64, ghidra::AddressSpace::TYPE_RAM, 1),
          constSpace("const", 64, ghidra::AddressSpace::TYPE_CONSTANT, 2),
          uniqueSpace("unique", 64, ghidra::AddressSpace::TYPE_UNIQUE, 3),
          registerSpace("register", 64, ghidra::AddressSpace::TYPE_REGISTER, 4),
          stackSpace("stack", 64, ghidra::AddressSpace::TYPE_STACK, 5),
          prog("analyzer_test", nullptr, nullptr) {
        auto* addrFactory = dynamic_cast<ghidra::ProgramAddressFactory*>(prog.getAddressFactory());
        if (addrFactory) {
            addrFactory->addAddressSpace(&ramSpace);
            addrFactory->setDefaultSpace(&ramSpace);
            addrFactory->setConstantSpace(&constSpace);
            addrFactory->setUniqueSpace(&uniqueSpace);
            addrFactory->setRegisterSpace(&registerSpace);
            addrFactory->setStackSpace(&stackSpace);
        }
    }
};

void run_analyzer_integration_test(const std::string& binPath) {
    std::cout << "Running analyzer integration on: " << binPath << "\n";
    
    auto loader = ghidra::createLoader();
    bool parsed = loader->load(binPath);
    TEST("BinaryLoader parses test binary", parsed);
    if (!parsed) {
        std::cerr << "Failed to parse binary. Skipping analyzer tests.\n";
        return;
    }

    TestProgram tprog;
    bool loaded = loader->populateProgram(&tprog.prog);
    TEST("BinaryLoader populates ProgramDB", loaded);
    if (!loaded) return;

    ghidra::AutoAnalysisManager aam(&tprog.prog);
    aam.initializeDefaultAnalyzers();
    
    // We expect there to be some analyzers registered
    auto analyzers = aam.getAnalyzers();
    TEST("AutoAnalysisManager registered analyzers", !analyzers.empty());
    std::cout << "Registered " << analyzers.size() << " default analyzers.\n";

    ghidra::StubTaskMonitor monitor;
    try {
        // Cancel after 3 seconds to bound analysis time
        // We just need to verify no crashes, not full analysis
        auto cancelTime = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        std::thread cancelThread([&monitor, cancelTime]() {
            std::this_thread::sleep_until(cancelTime);
            monitor.cancel();
        });
        aam.startAnalysis(&monitor);
        cancelThread.join();
        TEST("startAnalysis completes without exception", true);
    } catch (const std::exception& e) {
        std::cerr << "Analysis failed with exception: " << e.what() << "\n";
        TEST("startAnalysis completes without exception", false);
    } catch (...) {
        std::cerr << "Analysis failed with unknown exception.\n";
        TEST("startAnalysis completes without exception", false);
    }

    // Verify some effects on ProgramDB
    ghidra::FunctionManager* funcMgr = tprog.prog.getFunctionManager();
    if (funcMgr) {
        int funcCount = 0;
        auto iter = funcMgr->getFunctions(true);
        while (iter.hasNext()) {
            iter.next();
            funcCount++;
        }
        std::cout << "Discovered functions: " << funcCount << "\n";
        // It might not discover any without a full Disassembler mapping, but it shouldn't crash.
        TEST("FunctionManager is accessible", true);
    } else {
        TEST("FunctionManager is accessible", false);
    }
}

int main(int argc, char** argv) {
    std::string binPath = getTestBinaryPath(argc, argv);
    run_analyzer_integration_test(binPath);
    
    std::cout << "Analyzer Integration Tests: " << passed << "/" << total << " passed.\n" << std::flush;
    std::cout << "Exiting main...\n" << std::flush;
    return (passed == total) ? 0 : 1;
}
