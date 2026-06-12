#include <ghidra/FunctionStartFuncAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/FunctionIterator.h>
#include <ghidra/AddressSet.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/Reference.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/SourceType.h>
#include <ghidra/Msg.h>

namespace ghidra {

FunctionStartFuncAnalyzer::FunctionStartFuncAnalyzer()
    : AbstractAnalyzer("Function Start Search After Function",
                       "Function discovery variant of function start search.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FUNCTION_ANALYSIS.after());
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

bool FunctionStartFuncAnalyzer::canAnalyze(Program* program) const {
    return program != nullptr;
}

bool FunctionStartFuncAnalyzer::added(Program* program, const AddressSetView& set,
                                       TaskMonitor* monitor, MessageLog& log) {
    if (!program || !monitor) return false;
    monitor->setMessage("Finding function starts from function references...");

    Memory* memory = program->getMemory();
    FunctionManager* funcMgr = program->getFunctionManager();
    ReferenceManager* refMgr = program->getReferenceManager();
    if (!memory || !funcMgr || !refMgr) return true;

    int found = 0;
    FunctionIterator iter = funcMgr->getFunctions(true);
    while (iter.hasNext() && !monitor->isCancelled()) {
        Function* func = iter.next();
        Address entry = func->getEntryPoint();

        // Check call references from this function for potential function starts
        auto refsFrom = refMgr->getReferencesFrom(entry);
        for (auto* ref : refsFrom) {
            if (monitor->isCancelled()) break;
            if (!ref->getReferenceType()->isCall()) continue;

            Address toAddr = ref->getToAddress();
            if (!memory->getBlock(toAddr)) continue;
            if (funcMgr->getFunctionAt(toAddr) || funcMgr->getFunctionContaining(toAddr)) continue;

            AddressSet body(toAddr, toAddr);
            funcMgr->createFunction("func_call_" + std::to_string(toAddr.getOffset()),
                                    toAddr, body, SourceType::ANALYSIS);
            ++found;
        }
    }

    if (found > 0) {
        Msg::info(getName(), "Found " + std::to_string(found) + " function starts from calls.");
    }
    return true;
}

} // namespace ghidra
