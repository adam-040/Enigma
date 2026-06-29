/// enigma_fks_ingest.cpp
/// Analyzes a PE binary and extracts named functions into a .fkslib knowledge file.
/// Usage: enigma_fks_ingest <binary> <output.fkslib> [--family <name>] [--compiler <name>]

#include <ghidra/BinaryLoader.h>
#include <ghidra/ProgramDB.h>
#include <ghidra/Memory.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/ProgramAddressFactory.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/AutoAnalysisManager.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/FksLibrary.h>
#include <ghidra/FunctionFingerprint.h>
#include <ghidra/NamingService.h>
#include <ghidra/FunctionDiscoveryAnalyzer.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/AddressRange.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/RefType.h>
#include <ghidra/EntryPointAnalyzer.h>
#include <ghidra/DisassemblyAnalyzer.h>
#include <ghidra/FunctionStartAnalyzer.h>
#include <ghidra/FunctionStartDataPostAnalyzer.h>
#include <ghidra/FunctionStartFuncAnalyzer.h>
#include <ghidra/DataSectionFunctionScannerAnalyzer.h>
#include <ghidra/ApplyDataArchiveAnalyzer.h>
#include <ghidra/MainRecognitionAnalyzer.h>
#include <ghidra/FragmentMergeAnalyzer.h>
#include <ghidra/FidAnalyzer.h>
#include <ghidra/FunctionBodyFinalizer.h>
#include <ghidra/ExternalEntryFunctionAnalyzer.h>
#include <ghidra/DataRefFunctionAnalyzer.h>
#include <ghidra/PEExceptionAnalyzer.h>
#include <ghidra/ImportThunkAnalyzer.h>
#include <ghidra/ScalarOperandAnalyzer.h>
#include <ghidra/OperandReferenceAnalyzer.h>
#include <ghidra/DataOperandReferenceAnalyzer.h>
#include <ghidra/ConstantPropagationAnalyzer.h>
#include <ghidra/StackReferenceAnalyzer.h>
#include <ghidra/StackVariableAnalyzer.h>

#include <iostream>
#include <string>
#include <memory>
#include <filesystem>
#include <ctime>
#include <unordered_map>

using namespace ghidra;

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: enigma_fks_ingest <binary> <output.fkslib> "
                  << "[--family <name>] [--compiler <name>] [--version <ver>]\n";
        return 1;
    }

    std::string binaryPath = argv[1];
    std::string outputPath = argv[2];
    std::string family   = "unknown";
    std::string compiler = "unknown";
    std::string version  = "";

    for (int i = 3; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--family"   && i + 1 < argc) family   = argv[++i];
        else if (arg == "--compiler" && i + 1 < argc) compiler = argv[++i];
        else if (arg == "--version"  && i + 1 < argc) version  = argv[++i];
    }

    // Load binary
    auto loader = createLoader();
    if (!loader || !loader->load(binaryPath)) {
        std::cerr << "Failed to load: " << binaryPath << "\n";
        return 1;
    }

    // Setup address spaces
    auto* ramSpace = new GenericAddressSpace("ram", 64, AddressSpace::TYPE_RAM, 1);
    auto* constSpace = new GenericAddressSpace("const", 64, AddressSpace::TYPE_CONSTANT, 2);
    auto* uniqueSpace = new GenericAddressSpace("unique", 64, AddressSpace::TYPE_UNIQUE, 3);
    auto* regSpace = new GenericAddressSpace("register", 64, AddressSpace::TYPE_REGISTER, 4);
    auto* stackSpace = new GenericAddressSpace("stack", 64, AddressSpace::TYPE_STACK, 5);

    auto prog = std::make_unique<ProgramDB>("fks_ingest", nullptr, nullptr);
    auto* addrFactory = dynamic_cast<ProgramAddressFactory*>(prog->getAddressFactory());
    if (addrFactory) {
        addrFactory->addAddressSpace(ramSpace);
        addrFactory->addAddressSpace(constSpace);
        addrFactory->addAddressSpace(uniqueSpace);
        addrFactory->addAddressSpace(regSpace);
        addrFactory->addAddressSpace(stackSpace);
        addrFactory->setDefaultSpace(ramSpace);
    }

    if (!loader->populateProgram(prog.get())) {
        std::cerr << "populateProgram failed\n";
        return 1;
    }

    // Run FunctionDiscoveryAnalyzer first
    auto* fm = prog->getFunctionManager();
    {
        FunctionDiscoveryOptions fdOpts;
        fdOpts.includeExternalInFunctionManager = true;
        FunctionDiscoveryAnalyzer fdAnalyzer(fdOpts);
        fdAnalyzer.analyzeLoader(*loader);
        if (fm && ramSpace) {
            fdAnalyzer.applyTo(*fm, ramSpace);
        }
    }

    // Full analysis pipeline
    auto analysisMgr = std::make_unique<AutoAnalysisManager>(prog.get());
    analysisMgr->registerAnalyzer(std::make_unique<EntryPointAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<DisassemblyAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<FunctionStartAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<DataSectionFunctionScannerAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<FunctionStartDataPostAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<FunctionStartFuncAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<ApplyDataArchiveAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<ExternalEntryFunctionAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<PEExceptionAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<DataRefFunctionAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<ScalarOperandAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<OperandReferenceAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<DataOperandReferenceAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<ConstantPropagationAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<StackReferenceAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<StackVariableAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<FragmentMergeAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<ImportThunkAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<FidAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<MainRecognitionAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<FunctionBodyFinalizer>());

    analysisMgr->analyze(&ghidra::getDummyMonitor());

    // Build export address -> name map
    std::unordered_map<uint64_t, std::string> exportMap;
    {
        auto exports = loader->getExports();
        for (const auto& exp : exports) {
            if (!exp.name.empty()) {
                exportMap[exp.address] = exp.name;
            }
        }
        std::cerr << "  PE exports found:    " << exportMap.size() << "\n";
    }

    // Compute fingerprints and build FksLibrary
    FksLibrary lib;
    FksLibraryMeta meta;
    meta.family      = family;
    meta.version     = version;
    meta.compiler    = compiler;
    meta.language    = "x86:LE:64:default";
    meta.description = "Auto-generated from " + std::filesystem::path(binaryPath).filename().string();
    meta.created     = static_cast<uint64_t>(std::time(nullptr));
    lib.setMeta(meta);

    FunctionFingerprinter fingerprinter;
    auto* refMgr = prog->getReferenceManager();
    auto* listing = prog->getListing();
    auto* symTable = prog->getSymbolTable();

    int totalFuncs = 0;
    int namedFuncs = 0;
    int fingerprinted = 0;

    if (fm) {
        auto fit = fm->getFunctions(true);
        while (fit.hasNext()) {
            auto* func = fit.next();
            if (!func || func->isExternal()) continue;
            totalFuncs++;

            try {
                std::string name = func->getName();
                bool isExport = false;

                // Check if this function matches a PE export
                uint64_t entryOffset = func->getEntryPoint().getOffset();
                auto expIt = exportMap.find(entryOffset);
                if (expIt != exportMap.end()) {
                    name = expIt->second;
                    isExport = true;
                } else if (NamingService::isAutoGeneratedName(name)) {
                    continue;
                }
                namedFuncs++;

            // Compute fingerprint
            FunctionFingerprint fp = fingerprinter.compute(func, prog.get());

            // Compute body size from AddressSet (returned by value)
            uint32_t bodySize = 0;
            const AddressSet& bodySet = func->getBody();
            auto* bodyIter = bodySet.getAddressRanges();
            while (bodyIter->hasNext()) {
                AddressRange range = bodyIter->next();
                bodySize += static_cast<uint32_t>(
                    range.getMaxAddress().getOffset() - range.getMinAddress().getOffset() + 1);
            }

            // Count basic blocks (approximate: count of address ranges in body)
            uint16_t bbCount = 1;
            if (bodySet.getNumAddressRanges() > 1) {
                bbCount = static_cast<uint16_t>(bodySet.getNumAddressRanges());
            }

            // Count calls from this function
            uint16_t callCount = 0;
            if (refMgr) {
                auto refs = refMgr->getReferencesFrom(func->getEntryPoint());
                for (auto* ref : refs) {
                    const RefType* rt = ref->getReferenceType();
                    if (rt && rt->isCall()) callCount++;
                }
            }

            // Count instructions
            uint16_t instrCount = 0;
            if (listing) {
                auto* addrIter = bodySet.getAddressRanges();
                while (addrIter->hasNext()) {
                    AddressRange range = addrIter->next();
                    Address curAddr = range.getMinAddress();
                    Address maxAddr = range.getMaxAddress();
                    while (curAddr.getOffset() <= maxAddr.getOffset()) {
                        try {
                            auto* instr = listing->getInstructionAt(curAddr);
                            if (!instr) break;
                            instrCount++;
                            curAddr = curAddr.add(static_cast<int64_t>(instr->getLength()));
                        } catch (...) {
                            break;
                        }
                    }
                }
            }

            FksFunction fkFunc;
            fkFunc.uid         = fp.fullHash();
            fkFunc.name        = name;
            fkFunc.nameDemangled = "";
            fkFunc.hashes.fullHash  = fp.v1.fullHash;
            fkFunc.hashes.shortHash = fp.v1.shortHash;
            fkFunc.hashes.mnemHash  = fp.v1.mnemHash;
            fkFunc.hashes.callHash  = fp.v1.callHash;
            fkFunc.hashesV2.fullHash  = fp.v2.fullHash;
            fkFunc.hashesV2.shortHash = fp.v2.shortHash;
            fkFunc.hashesV2.mnemHash  = fp.v2.mnemHash;
            fkFunc.hashesV2.callHash  = fp.v2.callHash;
            fkFunc.bodySize    = bodySize;
            fkFunc.instrCount  = instrCount;
            fkFunc.callCount   = callCount;
            fkFunc.basicBlocks = bbCount;
            fkFunc.cyclomatic   = (bbCount > 1) ? static_cast<uint16_t>(callCount - bbCount + 2) : 0;
            fkFunc.hasFrame    = (func->getStackFrame() != nullptr);
            fkFunc.exported    = isExport;
            fkFunc.virtualAddress = func->getEntryPoint().getOffset();

            lib.addFunction(fkFunc);
            fingerprinted++;
            } catch (...) { /* skip functions that cause memory exceptions */ }
        }
    }

    // Save
    if (!lib.saveToFile(outputPath)) {
        std::cerr << "Failed to save: " << outputPath << "\n";
        return 1;
    }

    std::cerr << "Ingested " << binaryPath << "\n";
    std::cerr << "  Total functions:    " << totalFuncs << "\n";
    std::cerr << "  Named (non-auto):  " << namedFuncs << "\n";
    std::cerr << "  Fingerprinted:     " << fingerprinted << "\n";
    std::cerr << "  Output:            " << outputPath << "\n";

    return 0;
}
