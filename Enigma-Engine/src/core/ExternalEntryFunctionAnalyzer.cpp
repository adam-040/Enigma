#include <ghidra/ExternalEntryFunctionAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/AddressSet.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <iostream>

namespace ghidra {

namespace {

bool isGoodFunctionStart(const Program* program, const Address& addr) {
    // External entry points (from .pdata, exports, etc.) are compiler-guaranteed
    // function starts. No instruction-existence check needed — this analyzer runs
    // before disassembly. Only reject if already inside an existing function body.
    auto* funcMgr = program->getFunctionManager();
    if (!funcMgr) return true;
    if (funcMgr->getFunctionContaining(addr)) return false;
    if (funcMgr->getFunctionAt(addr)) return false;
    return true;
}

} // anonymous namespace

ExternalEntryFunctionAnalyzer::ExternalEntryFunctionAnalyzer()
    : AbstractAnalyzer("External Entry References",
                       "Creates function definitions for external entry points (.pdata, exports).",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::CODE_ANALYSIS.before().before());
    setDefaultEnablement(true);
}

bool ExternalEntryFunctionAnalyzer::added(Program* program, const AddressSetView& set,
                                           TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    auto* symTable = program->getSymbolTable();
    auto* listing = program->getListing();
    auto* funcMgr = program->getFunctionManager();
    auto* memory = program->getMemory();
    if (!symTable || !listing || !funcMgr || !memory) return false;

    if (monitor) {
        monitor->setMessage("Finding External Entry Functions");
    }

    AddressSet funcStarts;

    auto entryPoints = symTable->getExternalEntryPoints();
    std::cerr << "[INFO] ExternalEntryFunctionAnalyzer: processing " << entryPoints.size()
              << " external entry points" << std::endl;
    int eeIter_ = 0;
    int eeSkipped_ = 0;
    int eeGood_ = 0;
    for (const Address& entry : entryPoints) {
        if (monitor && monitor->isCancelled()) return false;
        ++eeIter_;
        if (eeIter_ % 5000 == 0) {
            std::cerr << "[INFO] ExternalEntryFunctionAnalyzer: iter=" << eeIter_
                      << " good=" << eeGood_ << " skipped=" << eeSkipped_ << std::endl;
        }

        if (!set.contains(entry)) { ++eeSkipped_; continue; }

        MemoryBlock* block = memory->getBlock(entry);
        if (!block || !block->isExecute()) { ++eeSkipped_; continue; }

        if (!isGoodFunctionStart(program, entry)) { ++eeSkipped_; continue; }

        funcStarts.add(entry);
        ++eeGood_;
    }
    std::cerr << "[INFO] ExternalEntryFunctionAnalyzer: phase1 done, good=" << eeGood_
              << " skipped=" << eeSkipped_ << std::endl;

    // Remove addresses that are already functions
    AddressSet alreadyFuncSet;
    for (const Address& entry : entryPoints) {
        if (funcStarts.contains(entry) && funcMgr->getFunctionAt(entry)) {
            alreadyFuncSet.add(entry);
        }
    }
    funcStarts.remove(alreadyFuncSet);

    if (monitor && monitor->isCancelled()) return false;

    // Create functions at the remaining entry points
    if (!funcStarts.isEmpty()) {
        std::cerr << "[INFO] ExternalEntryFunctionAnalyzer: creating functions at "
                  << funcStarts.getNumAddresses() << " entry points" << std::endl;
        auto* rangeIter = funcStarts.getAddressRanges(true);
        int createIter_ = 0;
        while (rangeIter->hasNext()) {
            if (monitor && monitor->isCancelled()) break;
            const AddressRange& range = rangeIter->next();
            Address addr = range.getMinAddress();
            while (addr <= range.getMaxAddress()) {
                try {
                    funcMgr->createFunction("", addr, AddressSet(addr, addr),
                                            SourceType::ANALYSIS);
                } catch (const std::exception&) {
                }
                ++createIter_;
                if (createIter_ % 5000 == 0) {
                    std::cerr << "[INFO] ExternalEntryFunctionAnalyzer: create iter=" << createIter_ << std::endl;
                }
                if (addr == range.getMaxAddress()) break;
                addr = addr.next();
            }
        }
        std::cerr << "[INFO] ExternalEntryFunctionAnalyzer: phase2 done, created=" << createIter_ << std::endl;
    }

    return true;
}

} // namespace ghidra
