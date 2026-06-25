/// enigma_binary_audit.cpp
/// Lightweight tool: loads a PE and dumps structural statistics
/// without running the full decompiler pipeline.

#include <ghidra/BinaryLoader.h>
#include <ghidra/ProgramDB.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/ExternalManager.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/ProgramAddressFactory.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/AutoAnalysisManager.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/EntryPointAnalyzer.h>
#include <ghidra/DisassemblyAnalyzer.h>
#include <ghidra/FunctionStartAnalyzer.h>
#include <ghidra/FunctionStartDataPostAnalyzer.h>
#include <ghidra/FunctionStartFuncAnalyzer.h>
#include <ghidra/ApplyDataArchiveAnalyzer.h>
#include <ghidra/FragmentMergeAnalyzer.h>
#include <ghidra/FidAnalyzer.h>
#include <ghidra/MainRecognitionAnalyzer.h>
#include <ghidra/ExternalEntryFunctionAnalyzer.h>
#include <ghidra/FunctionDiscoveryAnalyzer.h>
#include <ghidra/DataRefFunctionAnalyzer.h>
#include <ghidra/PEExceptionAnalyzer.h>

#include <iostream>
#include <string>
#include <memory>
#include <cstdlib>

using namespace ghidra;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: enigma_binary_audit <binary>\n";
        return 1;
    }

    std::string path = argv[1];

    fprintf(stderr, "starting...\n"); fflush(stderr);

    // --- Load binary ---
    fprintf(stderr, "creating loader...\n"); fflush(stderr);
    auto loader = ghidra::createLoader();
    if (!loader) {
        std::cerr << "Failed to create loader for: " << path << "\n";
        return 1;
    }

    fprintf(stderr, "calling load...\n"); fflush(stderr);
    if (!loader->load(path)) {
        std::cerr << "Failed to load: " << path << "\n";
        return 1;
    }
    fprintf(stderr, "load done\n"); fflush(stderr);

    std::cout << "=== BINARY STRUCTURE ===\n";
    std::cout << "Format: " << loader->getFormatName() << "\n";
    std::cout << "Arch: " << loader->getArchitecture() << "\n";
    std::cout << "Bitness: " << loader->getBitness() << "\n";
    std::cout << "ImageBase: 0x" << std::hex << loader->getImageBase() << std::dec << "\n";
    std::cout << "EntryPoint: 0x" << std::hex << loader->getEntryPoint() << std::dec << "\n";

    auto sections = loader->getSections();
    fprintf(stderr, "done sections\n"); fflush(stderr);
    std::cout << "\nSections (" << sections.size() << "):\n";
    for (auto& sec : sections) {
        std::cout << "  " << sec.name << ": "
                  << "0x" << std::hex << sec.virtualAddress
                  << " - 0x" << (sec.virtualAddress + sec.virtualSize)
                  << " (size=" << sec.virtualSize << ", file=" << sec.fileSize << ")"
                  << " type=" << sec.type
                  << " r=" << sec.isReadable << " w=" << sec.isWritable << " x=" << sec.isExecutable
                  << std::dec << "\n";
    }
    fprintf(stderr, "done section loop\n"); fflush(stderr);

    auto exports = loader->getExports();
    fprintf(stderr, "done getExports: %zu\n", exports.size()); fflush(stderr);
    std::cout << "\nExports: " << exports.size() << "\n";
    std::cout.flush();

    auto imports = loader->getImports();
    fprintf(stderr, "done getImports: %zu\n", imports.size()); fflush(stderr);
    std::cout << "Imports: " << imports.size() << "\n";
    std::cout.flush();

    auto symbols = loader->getSymbols();
    fprintf(stderr, "done getSymbols: %zu\n", symbols.size()); fflush(stderr);
    int funcSyms = 0;
    for (auto& s : symbols) if (s.isFunction) funcSyms++;
    std::cout << "Symbols: " << symbols.size() << " (functions: " << funcSyms << ")\n";

    fprintf(stderr, "done symbols\n"); fflush(stderr);

    // --- Create ProgramDB and populate ---
    fprintf(stderr, "creating spaces...\n"); fflush(stderr);
    auto* ramSpace = new GenericAddressSpace("ram", 64, AddressSpace::TYPE_RAM, 1);
    auto* constSpace = new GenericAddressSpace("const", 64, AddressSpace::TYPE_CONSTANT, 2);
    auto* uniqueSpace = new GenericAddressSpace("unique", 64, AddressSpace::TYPE_UNIQUE, 3);
    auto* regSpace = new GenericAddressSpace("register", 64, AddressSpace::TYPE_REGISTER, 4);
    auto* stackSpace = new GenericAddressSpace("stack", 64, AddressSpace::TYPE_STACK, 5);

    auto prog = std::make_unique<ProgramDB>("audit", nullptr, nullptr);
    auto* addrFactory = dynamic_cast<ProgramAddressFactory*>(prog->getAddressFactory());
    if (addrFactory) {
        addrFactory->addAddressSpace(ramSpace);
        addrFactory->addAddressSpace(constSpace);
        addrFactory->addAddressSpace(uniqueSpace);
        addrFactory->addAddressSpace(regSpace);
        addrFactory->addAddressSpace(stackSpace);
        addrFactory->setDefaultSpace(ramSpace);
    }
    fprintf(stderr, "done creating spaces\n"); fflush(stderr);

    fprintf(stderr, "calling populateProgram...\n"); fflush(stderr);
    if (!loader->populateProgram(prog.get())) {
        std::cerr << "populateProgram failed\n";
        return 1;
    }
    fprintf(stderr, "done populateProgram\n"); fflush(stderr);

    // --- Dump populate results ---
    auto* fm = prog->getFunctionManager();
    auto* symTable = prog->getSymbolTable();
    auto* listing = prog->getListing();
    int funcCount = fm ? fm->getFunctionCount() : -1;
    int symCount = symTable ? symTable->getNumSymbols() : -1;
    int instCount = listing ? listing->getInstructionCount() : -1;

    std::cout << "\n=== AFTER populateProgram ===\n";
    std::cout << "Functions: " << funcCount << "\n";
    std::cout << "Symbols: " << symCount << "\n";
    std::cout << "Instructions: " << instCount << "\n";

    // --- FunctionDiscoveryAnalyzer: import thunks, exports, etc. ---
    {
        FunctionDiscoveryOptions fdOpts;
        fdOpts.includeExternalInFunctionManager = true;
        FunctionDiscoveryAnalyzer fdAnalyzer(fdOpts);
        fdAnalyzer.analyzeLoader(*loader);
        if (fm && ramSpace) {
            auto fdResult = fdAnalyzer.applyTo(*fm, ramSpace);
            std::cout << "\n=== FUNCTION DISCOVERY ANALYZER ===\n";
            std::cout << "  Created: " << fdResult.createdFunctions << " functions\n";
            std::cout << "  Skipped (existing): " << fdResult.skippedExisting << "\n";
            std::cout << "  Skipped (external): " << fdResult.skippedExternal << "\n";
            std::cout << "  Failed: " << fdResult.failedCreates << "\n";
            std::cout << "  Candidates: " << fdResult.candidates.size() << "\n";
            auto* pfm = prog->getFunctionManager();
            std::cout << "  Total functions after: " << (pfm ? pfm->getFunctionCount() : -1) << "\n";
        }
    }

    // Dump functions
    if (fm) {
        auto fit = fm->getFunctions(true);
        int i = 0;
        while (fit.hasNext() && i < 20) {
            auto* f = fit.next();
            if (f) {
                std::cout << "  FUNC[" << i << "] 0x"
                          << std::hex << f->getEntryPoint().getOffset()
                          << std::dec << " '" << f->getName() << "'\n";
                i++;
            }
        }
        if (i == 0) std::cout << "  (no functions)\n";
    }

    // --- Run AutoAnalysis ---
    std::cout << "=== RUNNING ANALYSIS ===\n";
    std::cout.flush();

    fprintf(stderr, "creating analysisMgr...\n"); fflush(stderr);

    auto analysisMgr = std::make_unique<AutoAnalysisManager>(prog.get());
    fprintf(stderr, "done creating analysisMgr\n"); fflush(stderr);

    // Register only the analyzers we need for function discovery:
    analysisMgr->registerAnalyzer(std::make_unique<EntryPointAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<DisassemblyAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<FunctionStartAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<FunctionStartDataPostAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<FunctionStartFuncAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<ApplyDataArchiveAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<ExternalEntryFunctionAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<ghidra::PEExceptionAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<DataRefFunctionAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<FragmentMergeAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<FidAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<MainRecognitionAnalyzer>());
    fprintf(stderr, "done register analyzers\n"); fflush(stderr);

    std::cout << "Before analysis:\n";
    std::cout << "  Functions: " << (fm ? fm->getFunctionCount() : -1) << "\n";
    std::cout << "  Instructions: " << (listing ? listing->getInstructionCount() : -1) << "\n";
    std::cout << "  Data: " << (listing ? listing->getDataCount() : -1) << "\n";
    std::cout.flush();

    fprintf(stderr, "analyzing...\n"); fflush(stderr);
    analysisMgr->analyze(&ghidra::getDummyMonitor());
    fprintf(stderr, "done analyzing\n"); fflush(stderr);

    std::cout << "\nAfter analysis:\n";
    std::cout << "  Functions: " << (fm ? fm->getFunctionCount() : -1) << "\n";
    std::cout << "  Instructions: " << (listing ? listing->getInstructionCount() : -1) << "\n";
    std::cout << "  Data: " << (listing ? listing->getDataCount() : -1) << "\n";

    if (fm) {
        auto fit = fm->getFunctions(true);
        int i = 0;
        while (fit.hasNext() && i < 30) {
            auto* f = fit.next();
            if (f) {
                std::cout << "  FUNC[" << i << "] 0x"
                          << std::hex << f->getEntryPoint().getOffset()
                          << std::dec << " '" << f->getName() << "'\n";
                i++;
            }
        }
        if (i == 0) std::cout << "  (no functions)\n";
        else std::cout << "  ... (" << i << " shown)\n";
    }

    return 0;
}
