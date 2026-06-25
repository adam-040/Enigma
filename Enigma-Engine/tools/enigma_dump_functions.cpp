/// enigma_dump_functions.cpp
/// Dumps function addresses and names from a PE binary in CSV format
/// Output: address,type,name (type: thunk|prologue|discovery|entry)
/// Usage: enigma_dump_functions <binary> [--ghidra-compat]

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
#include <ghidra/AddressRange.h>
#include <ghidra/AutoAnalysisManager.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
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
#include <ghidra/FunctionDiscoveryAnalyzer.h>
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
#include <cstdlib>
#include <cstdio>
#include <set>

using namespace ghidra;

struct FuncEntry {
    uint64_t address;
    std::string name;
    std::string type; // "thunk", "prologue", "discovery", "entry"
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: enigma_dump_functions <binary> [--ghidra-compat]\n";
        return 1;
    }

    std::string path = argv[1];
    bool ghidraCompat = false;
    for (int i = 2; i < argc; i++) {
        if (std::string(argv[i]) == "--ghidra-compat") ghidraCompat = true;
    }

    auto loader = createLoader();
    if (!loader || !loader->load(path)) {
        std::cerr << "Failed to load: " << path << "\n";
        return 1;
    }

    auto* ramSpace = new GenericAddressSpace("ram", 64, AddressSpace::TYPE_RAM, 1);
    auto* constSpace = new GenericAddressSpace("const", 64, AddressSpace::TYPE_CONSTANT, 2);
    auto* uniqueSpace = new GenericAddressSpace("unique", 64, AddressSpace::TYPE_UNIQUE, 3);
    auto* regSpace = new GenericAddressSpace("register", 64, AddressSpace::TYPE_REGISTER, 4);
    auto* stackSpace = new GenericAddressSpace("stack", 64, AddressSpace::TYPE_STACK, 5);

    auto prog = std::make_unique<ProgramDB>("dump", nullptr, nullptr);
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

    auto* fm = prog->getFunctionManager();
    auto* listing = prog->getListing();

    // FunctionDiscoveryAnalyzer for thunks
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
    analysisMgr->registerAnalyzer(std::make_unique<ghidra::PEExceptionAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<DataRefFunctionAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<ScalarOperandAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<OperandReferenceAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<DataOperandReferenceAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<ConstantPropagationAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<StackReferenceAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<StackVariableAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<FragmentMergeAnalyzer>());
    // Late import thunk detection — catches thunks whose JMP references
    // were created by earlier function-start / reference analyzers.
    analysisMgr->registerAnalyzer(std::make_unique<ImportThunkAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<FidAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<MainRecognitionAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<FunctionBodyFinalizer>());

    analysisMgr->analyze(&ghidra::getDummyMonitor());

    // Collect all functions
    std::vector<FuncEntry> funcs;
    if (fm) {
        auto fit = fm->getFunctions(true);
        while (fit.hasNext()) {
            auto* f = fit.next();
            if (!f) continue;

            FuncEntry e;
            e.address = f->getEntryPoint().getOffset();
            e.name = f->getName();

            // Classify function type
            std::string& n = e.name;
            if (n.find("thunk_") == 0 || n.find("FUN_") == 0) {
                AddressSet bodySet = f->getBody();
                if (bodySet.getNumAddressRanges() > 0) {
                    auto* it = bodySet.getAddressRanges();
                    if (it->hasNext()) {
                        AddressRange r = it->next();
                        if (r.getMaxAddress().getOffset() - r.getMinAddress().getOffset() <= 16) {
                            e.type = "thunk";
                        } else {
                            e.type = (n.find("func_start_") == 0) ? "prologue" : "discovery";
                        }
                    } else {
                        e.type = "discovery";
                    }
                } else {
                    e.type = "discovery";
                }
            } else if (n == "entry") {
                e.type = "entry";
            } else {
                e.type = "named";
            }

            funcs.push_back(e);
        }
    }

    // Output as CSV
    if (ghidraCompat) {
        // Ghidra-compatible CSV: address,name (with header for compare_function_lists.py)
        std::cout << "address,name\n";
        for (auto& f : funcs) {
            std::cout << "0x" << std::hex << f.address << std::dec << "," << f.name << "\n";
        }
    } else {
        // Full format: address,type,name
        std::cout << "address,type,name\n";
        for (auto& f : funcs) {
            std::cout << "0x" << std::hex << f.address << std::dec << "," << f.type << "," << f.name << "\n";
        }
    }

    return 0;
}
