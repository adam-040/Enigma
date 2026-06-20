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
                       "Creates functions at direct CALL targets that lack standard prologues.",
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
    monitor->setMessage("Creating functions at CALL targets...");

    Memory* memory = program->getMemory();
    FunctionManager* funcMgr = program->getFunctionManager();
    ReferenceManager* refMgr = program->getReferenceManager();
    Listing* listing = program->getListing();
    if (!memory || !funcMgr || !refMgr || !listing) return true;

    int found = 0;
    int skippedDataSection = 0;
    int skippedHasFunc = 0;

    std::vector<Instruction*> instructions = listing->getAllInstructions();
    for (Instruction* inst : instructions) {
        if (monitor->isCancelled()) break;
        if (!inst) continue;

        FlowType* ft = inst->getFlowType();
        if (!ft || !ft->isCall() || ft->isComputed()) continue;

        Address fromAddr = inst->getAddress();
        auto refs = refMgr->getReferencesFrom(fromAddr);
        if (refs.empty()) continue;

        for (Reference* ref : refs) {
            if (monitor->isCancelled()) break;
            if (!ref || !ref->getReferenceType()->isCall()) continue;

            Address toAddr = ref->getToAddress();
            if (!toAddr.isValid()) continue;

            MemoryBlock* block = memory->getBlock(toAddr);
            if (!block || !block->isExecute()) { ++skippedDataSection; continue; }

            if (funcMgr->getFunctionAt(toAddr)) { ++skippedHasFunc; continue; }
            if (funcMgr->getFunctionContaining(toAddr)) { ++skippedHasFunc; continue; }

            AddressSet body(toAddr, toAddr);
            funcMgr->createFunction("", toAddr, body, SourceType::ANALYSIS);
            ++found;
        }
    }

    if (found > 0 || skippedDataSection > 0) {
        Msg::info(getName(),
                  "Created " + std::to_string(found) + " functions at CALL targets "
                  "(skipped " + std::to_string(skippedDataSection) + " in non-executable sections).");
    }
    return true;
}

} // namespace ghidra
