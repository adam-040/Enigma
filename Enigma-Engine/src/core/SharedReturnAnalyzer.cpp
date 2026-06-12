#include <ghidra/SharedReturnAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/Reference.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/FunctionIterator.h>
#include <ghidra/Function.h>
#include <ghidra/AddressSet.h>
#include <ghidra/RefType.h>
#include <ghidra/FlowOverride.h>
#include <ghidra/Options.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>

namespace ghidra {

SharedReturnAnalyzer::SharedReturnAnalyzer()
    : AbstractAnalyzer("Shared Return Calls",
                       "Converts branches to calls, followed by an immediate return, "
                       "when the destination is a function.",
                       AnalyzerType::FUNCTION_ANALYZER) {
    setPriority(AnalysisPriority::CODE_ANALYSIS.before().before());
    setSupportsOneTimeAnalysis();
}

SharedReturnAnalyzer::SharedReturnAnalyzer(const std::string& name, const std::string& description, AnalyzerType type)
    : AbstractAnalyzer(name, description, type) {
    setPriority(AnalysisPriority::CODE_ANALYSIS.before().before());
    setSupportsOneTimeAnalysis(true);
}

bool SharedReturnAnalyzer::added(Program* program, const AddressSetView& set,
                                  TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    auto* listing = program->getListing();
    auto* refMgr = program->getReferenceManager();
    auto* funcMgr = program->getFunctionManager();
    if (!listing || !refMgr || !funcMgr) return false;

    FunctionIterator funcIter = funcMgr->getFunctions(set);
    if (monitor) {
        monitor->initialize(static_cast<int4>(funcIter.remaining()));
    }

    int count = 0;
    while (funcIter.hasNext()) {
        if (monitor && monitor->isCancelled()) break;
        if (monitor) monitor->setProgress(++count);

        Function* func = funcIter.next();
        if (!func) continue;

        Address entry = func->getEntryPoint();
        auto refsTo = refMgr->getReferencesTo(entry);

        for (auto* ref : refsTo) {
            if (!ref) continue;
            const RefType* refType = ref->getReferenceType();
            if (!refType) continue;

            if (!refType->isJump()) continue;
            if (refType->isCall()) continue;
            if (!considerConditionalBranches_ && refType->isConditional()) continue;

            Address fromAddr = ref->getFromAddress();
            Instruction* instr = listing->getInstructionAt(fromAddr);
            if (!instr) continue;

            Address fallThru = instr->getFallThrough();
            if (!fallThru.isValid()) continue;

            if (assumeContiguousFunctions_) {
                Function* containingFunc = funcMgr->getFunctionContaining(fallThru);
                if (containingFunc && containingFunc->getEntryPoint() == fallThru) {
                    instr->setFlowOverride(FlowOverride::CALL_RETURN);
                }
            } else {
                Function* targetFunc = funcMgr->getFunctionContaining(fallThru);
                if (targetFunc && targetFunc != funcMgr->getFunctionContaining(fromAddr)) {
                    instr->setFlowOverride(FlowOverride::CALL_RETURN);
                }
            }
        }
    }

    return true;
}

bool SharedReturnAnalyzer::getDefaultEnablement(Program* program) const {
    return true;
}

void SharedReturnAnalyzer::registerOptions(Options& options, Program* program) {
    options.registerBool("Assume Contiguous Functions Only", assumeContiguousFunctions_,
                         "Assume all function bodies are contiguous.");
    options.registerBool("Allow Conditional Jumps", considerConditionalBranches_,
                         "Allow conditional jumps to be considered for shared return.");
}

void SharedReturnAnalyzer::optionsChanged(Options& options, Program* program) {
    if (options.hasOption("Assume Contiguous Functions Only"))
        assumeContiguousFunctions_ = options.getBool("Assume Contiguous Functions Only");
    if (options.hasOption("Allow Conditional Jumps"))
        considerConditionalBranches_ = options.getBool("Allow Conditional Jumps");
}

} // namespace ghidra
