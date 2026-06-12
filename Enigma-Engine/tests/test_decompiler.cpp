/**
 * Enigma Engine - Decompiler Integration Test
 * Tests the Ghidra C++ decompiler library integration with SLEIGH specs
 */
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <sstream>
#include <cstdlib>

#include "ghidra/DecompilerAdapter.h"
#include "ghidra/BinaryLoader.h"
#include "ghidra/Msg.h"

int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;}else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

#ifndef ENIGMA_SLEIGH_DIR
#define ENIGMA_SLEIGH_DIR ""
#endif

static std::string getTestBinaryPath(int argc, char** argv) {
    const char* envPath = std::getenv("ENIGMA_TEST_BINARY");
    if (envPath && *envPath) {
        return envPath;
    }
    if (argc > 0 && argv && argv[0] && *argv[0]) {
        return argv[0];
    }
    return "enigma_test_decompiler.exe";
}

static std::string getSleighRoot() {
    const char* envPath = std::getenv("ENIGMA_SLEIGH_DIR");
    if (envPath && *envPath) {
        return envPath;
    }
    return ENIGMA_SLEIGH_DIR;
}

int main(int argc, char** argv) {
    std::cout << "=== Enigma Engine - Decompiler Integration Test ===" << std::endl;

    // Test 1: Create DecompilerAdapter
    std::cout << "\n--- Test 1: Adapter Creation ---" << std::endl;
    auto adapter = ghidra::createDecompilerAdapter();
    TEST("Adapter created", adapter != nullptr);

    // Test 2: Get decompiler version
    std::cout << "\n--- Test 2: Decompiler Version ---" << std::endl;
    std::string version = adapter->getDecompilerVersion();
    TEST("Version string not empty", !version.empty());
    std::cout << "  Version: " << version << std::endl;

    // Test 3: Set options
    std::cout << "\n--- Test 3: Set Options ---" << std::endl;
    adapter->setOption("timeout", "30");
    TEST("Set option (no crash)", true);

    // Test 4: Null function handling
    std::cout << "\n--- Test 4: Null Function Handling ---" << std::endl;
    ghidra::DecompiledFunction nullResult = adapter->decompileFunction(nullptr, 30);
    TEST("Null function handled", !nullResult.success);
    TEST("Null function has warning", !nullResult.warnings.empty());

    // Test 5: P-code with null function
    std::cout << "\n--- Test 5: P-code with Null Function ---" << std::endl;
    std::vector<ghidra::PcodeOutput> pcode;
    adapter->generatePcode(nullptr, pcode);
    TEST("P-code with null returns empty", pcode.empty());

    // Test 6: SLEIGH spec check
    std::cout << "\n--- Test 6: SLEIGH Spec Check ---" << std::endl;
    std::string sleighRoot = getSleighRoot();
    std::vector<std::string> specPaths = {
        sleighRoot + "/x86/x86.sla",
        sleighRoot + "/ARM/ARM4_le.sla",
        sleighRoot + "/AARCH64/AARCH64.sla",
    };
    int foundSpecs = 0;
    for (const auto& path : specPaths) {
        std::ifstream test(path);
        if (test.good()) {
            foundSpecs++;
            std::cout << "  Found: " << path << std::endl;
        }
    }
    TEST("SLEIGH spec directories exist", foundSpecs > 0);

    // Test 7: Load binary via BinaryLoader
    std::cout << "\n--- Test 7: Load Binary via Loader ---" << std::endl;
    std::string binaryPath = getTestBinaryPath(argc, argv);
    auto loader = ghidra::createLoader();
    bool loaded = loader->load(binaryPath);
    TEST("Binary loaded", loaded);

    if (loaded) {
        std::cout << "  Format: " << loader->getFormatName() << std::endl;
        std::cout << "  Arch: " << loader->getArchitecture() << std::endl;
        std::cout << "  Bitness: " << loader->getBitness() << std::endl;
        std::cout << "  Entry: 0x" << std::hex << loader->getEntryPoint() << std::dec << std::endl;
        std::cout << "  ImageBase: 0x" << std::hex << loader->getImageBase() << std::dec << std::endl;
        std::cout << "  Sections: " << loader->getSections().size() << std::endl;
        std::cout << "  Imports: " << loader->getImports().size() << std::endl;
        std::cout << "  Exports: " << loader->getExports().size() << std::endl;

        // Test 8: Language/Compiler guessing
        std::cout << "\n--- Test 8: Language/Compiler Guessing ---" << std::endl;
        std::string langStr = ghidra::BinaryLoader::guessLanguageFromArch(loader->getArchitecture(), loader->getBitness());
        std::string compStr = ghidra::BinaryLoader::guessCompilerSpecFromArch(loader->getArchitecture(), loader->getBitness());
        TEST("Language guessed", !langStr.empty() && langStr != "unknown");
        TEST("Compiler guessed", !compStr.empty());
        std::cout << "  Language: " << langStr << std::endl;
        std::cout << "  Compiler: " << compStr << std::endl;

        // Test 9: Read bytes from binary
        std::cout << "\n--- Test 9: Read Bytes ---" << std::endl;
        auto bytes = loader->getBytes(loader->getImageBase(), 16);
        TEST("Bytes read", bytes.size() == 16);
        bool hasMZ = (bytes[0] == 'M' && bytes[1] == 'Z');
        TEST("MZ header", hasMZ);
    }

    // Test 10: Library linkage verification
    std::cout << "\n--- Test 10: Library Linkage ---" << std::endl;
    auto adapter2 = ghidra::createDecompilerAdapter();
    TEST("Second adapter created", adapter2 != nullptr);
    TEST("Version works", !adapter2->getDecompilerVersion().empty());
    TEST("SetOption works", (adapter2->setOption("test", "value"), true));
    TEST("Decompile null works", !adapter2->decompileFunction(nullptr).success);
    std::vector<ghidra::PcodeOutput> pcode2;
    adapter2->generatePcode(nullptr, pcode2);
    TEST("Pcode null works", pcode2.empty());

    // Summary
    std::cout << "\n=== Summary ===" << std::endl;
    std::cout << passed << "/" << total << " tests passed" << std::endl;

    if (passed == total) {
        std::cout << "\nAll decompiler integration tests passed!" << std::endl;
    } else {
        std::cout << "\nSome tests failed. Check output above." << std::endl;
    }

    return (passed == total) ? 0 : 1;
}
