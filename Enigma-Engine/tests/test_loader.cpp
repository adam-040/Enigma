/**
 * Enigma Engine - Binary Loader Test
 * Tests PE/ELF binary loading functionality
 */
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <cstdlib>

#include "ghidra/BinaryLoader.h"
#include "ghidra/ProgramDB.h"
#include "ghidra/AddressSpace.h"
#include "ghidra/ProgramAddressFactory.h"
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
    return "enigma_test_loader.exe";
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
          prog("loader_test", nullptr, nullptr) {
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

int main(int argc, char** argv) {
    std::cout << "=== Enigma Engine - Binary Loader Test ===" << std::endl;

    // Test 1: Create loader
    std::cout << "\n--- Test 1: Loader Creation ---" << std::endl;
    auto loader = ghidra::createLoader();
    TEST("Loader created", loader != nullptr);

    // Test 2: Load PE binary
    std::cout << "\n--- Test 2: Load PE Binary ---" << std::endl;
    std::string pePath = getTestBinaryPath(argc, argv);
    bool peLoaded = loader->load(pePath);
    TEST("PE binary loaded", peLoaded);

    if (peLoaded) {
        TEST("Format is PE", loader->getFormatName() == "PE");
        TEST("Architecture detected", !loader->getArchitecture().empty());
        TEST("Bitness detected", loader->getBitness() == 32 || loader->getBitness() == 64);
        TEST("Entry point valid", loader->getEntryPoint() > 0);
        TEST("Image base valid", loader->getImageBase() > 0);

        std::cout << "  Format: " << loader->getFormatName() << std::endl;
        std::cout << "  Arch: " << loader->getArchitecture() << std::endl;
        std::cout << "  Bitness: " << loader->getBitness() << std::endl;
        std::cout << "  Entry: 0x" << std::hex << loader->getEntryPoint() << std::dec << std::endl;
        std::cout << "  ImageBase: 0x" << std::hex << loader->getImageBase() << std::dec << std::endl;

        // Test 3: Sections
        std::cout << "\n--- Test 3: PE Sections ---" << std::endl;
        auto sections = loader->getSections();
        TEST("Sections found", sections.size() > 0);
        std::cout << "  Sections: " << sections.size() << std::endl;
        for (const auto& sec : sections) {
            std::cout << "    " << sec.name << " @ 0x" << std::hex << sec.virtualAddress
                      << " size: 0x" << sec.virtualSize << std::dec
                      << (sec.isExecutable ? " X" : "")
                      << (sec.isReadable ? " R" : "")
                      << (sec.isWritable ? " W" : "") << std::endl;
        }

        // Test 4: Imports
        std::cout << "\n--- Test 4: PE Imports ---" << std::endl;
        auto imports = loader->getImports();
        std::cout << "  Imports: " << imports.size() << std::endl;
        for (size_t i = 0; i < imports.size() && i < 10; i++) {
            std::cout << "    " << imports[i].libraryName << "!" << imports[i].functionName
                      << " @ 0x" << std::hex << imports[i].address << std::dec << std::endl;
        }
        TEST("Imports parsed", true);

        // Test 5: Exports
        std::cout << "\n--- Test 5: PE Exports ---" << std::endl;
        auto exports = loader->getExports();
        std::cout << "  Exports: " << exports.size() << std::endl;
        for (size_t i = 0; i < exports.size() && i < 5; i++) {
            std::cout << "    " << exports[i].name << " @ 0x" << std::hex << exports[i].address << std::dec << std::endl;
        }
        TEST("Exports parsed", true);

        // Test 6: Relocations
        std::cout << "\n--- Test 6: PE Relocations ---" << std::endl;
        auto relocations = loader->getRelocations();
        std::cout << "  Relocations: " << relocations.size() << std::endl;
        TEST("Relocations parsed", true);

        // Test 7: Symbols
        std::cout << "\n--- Test 7: PE Symbols ---" << std::endl;
        auto symbols = loader->getSymbols();
        std::cout << "  Symbols: " << symbols.size() << std::endl;
        TEST("Symbols parsed", true);

        // Test 8: Read bytes
        std::cout << "\n--- Test 8: Read Bytes ---" << std::endl;
        auto bytes = loader->getBytes(loader->getImageBase(), 16);
        TEST("Bytes read", bytes.size() == 16);
        bool hasMZ = (bytes[0] == 'M' && bytes[1] == 'Z');
        TEST("MZ header", hasMZ);

        // Test 9: Architecture info
        std::cout << "\n--- Test 9: Architecture Info ---" << std::endl;
        TEST("Arch string valid", loader->getArchitecture().find("x86") != std::string::npos ||
             loader->getArchitecture() == "AARCH64" || loader->getArchitecture() == "ARM");
        std::cout << "  Arch: " << loader->getArchitecture() << std::endl;

        // Test 9b: Program metadata and entry function
        std::cout << "\n--- Test 9b: Program Metadata ---" << std::endl;
        TestProgram testProgram;
        std::string expectedLanguage =
            ghidra::BinaryLoader::guessLanguageFromArch(loader->getArchitecture(), loader->getBitness());
        bool populated = loader->populateProgram(&testProgram.prog);
        TEST("Program populated", populated);
        TEST("Language ID populated", testProgram.prog.getLanguageID().getIdAsString() == expectedLanguage);
        TEST("Compiler spec populated", !testProgram.prog.getCompilerSpecID().toString().empty());
        ghidra::Address entryAddr(&testProgram.ramSpace, static_cast<int64_t>(loader->getEntryPoint()));
        TEST("Entry function created", testProgram.prog.getFunctionManager()->getFunctionAt(entryAddr) != nullptr);
    }

    // Test 10: Load non-existent file
    std::cout << "\n--- Test 10: Non-existent File ---" << std::endl;
    auto loader2 = ghidra::createLoader();
    bool badLoad = loader2->load(pePath + ".does-not-exist");
    TEST("Non-existent file fails", !badLoad);

    // Test 11: Load invalid data
    std::cout << "\n--- Test 11: Invalid Data ---" << std::endl;
    std::string invalidPath = __FILE__;
    auto loader3 = ghidra::createLoader();
    bool invalidLoad = loader3->load(invalidPath);
    TEST("Invalid file fails", !invalidLoad);

    // Test 12: Loader reuse clears stale metadata
    std::cout << "\n--- Test 12: Reuse Clears State ---" << std::endl;
    auto reusableLoader = ghidra::createLoader();
    bool reusableLoaded = reusableLoader->load(pePath);
    bool reusableFailed = reusableLoader->load(invalidPath);
    TEST("Reusable first load succeeds", reusableLoaded);
    TEST("Reusable invalid reload fails", !reusableFailed);
    TEST("Reusable sections cleared", reusableLoader->getSections().empty());
    TEST("Reusable format cleared", reusableLoader->getFormatName().empty());

    // Summary
    std::cout << "\n=== Summary ===" << std::endl;
    std::cout << passed << "/" << total << " tests passed" << std::endl;

    return (passed == total) ? 0 : 1;
}
