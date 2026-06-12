#include <ghidra/SharedReturnJumpAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/Reference.h>
#include <ghidra/AddressIterator.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/RefType.h>
#include <ghidra/AddressSet.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>

namespace ghidra {

SharedReturnJumpAnalyzer::SharedReturnJumpAnalyzer()
    : SharedReturnAnalyzer("Shared Return Calls",
                           "Finds jump instructions that act as a shared return.",
                           AnalyzerType::INSTRUCTION_ANALYZER) {
    setPriority(AnalysisPriority::CODE_ANALYSIS.before().before());
    setSupportsOneTimeAnalysis(false);
}

bool SharedReturnJumpAnalyzer::added(Program* program, const AddressSetView& set,
                                      TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    auto* refMgr = program->getReferenceManager();
    auto* listing = program->getListing();
    auto* funcMgr = program->getFunctionManager();
    if (!refMgr || !listing || !funcMgr) return false;

    AddressSet sharedReturnSet;

    auto iter = refMgr->getReferenceSourceIterator(set, true);
    while (iter && iter->hasNext()) {
        if (monitor && monitor->isCancelled()) break;

        Address addr = iter->next();

        Instruction* instr = listing->getInstructionAt(addr);
        if (!instr) continue;

        FlowType* flowType = instr->getFlowType();
        if (!flowType || !flowType->isJump()) continue;

        auto refs = refMgr->getFlowReferencesFrom(addr);
        for (auto* ref : refs) {
            if (!ref) continue;
            const RefType* refType = ref->getReferenceType();
            if (!refType || !refType->isJump()) continue;

            Address entryAddr = ref->getToAddress();
            Function* funcAt = funcMgr->getFunctionAt(entryAddr);
            if (!funcAt) continue;

            sharedReturnSet.addRange(entryAddr, entryAddr);
        }
    }

    return SharedReturnAnalyzer::added(program, sharedReturnSet, monitor, log);
}

} // namespace ghidra
