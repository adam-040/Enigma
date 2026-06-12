#include <ghidra/X86FunctionPurgeAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Language.h>
#include <ghidra/Processor.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/Scalar.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/FunctionIterator.h>
#include <ghidra/Function.h>
#include <ghidra/StackFrame.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <string>

namespace ghidra {

X86FunctionPurgeAnalyzer::X86FunctionPurgeAnalyzer()
    : AbstractAnalyzer("X86 Function Callee Purge",
                       "Figures out the function Purge value for Callee cleaned up function call parameters (stdcall) on X86 platforms.",
                       AnalyzerType::FUNCTION_ANALYZER) {
    setPriority(AnalysisPriority::FUNCTION_ANALYSIS);
    setDefaultEnablement(true);
}

bool X86FunctionPurgeAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getLanguage()) return false;
    if (program->getLanguage()->getDefaultSpace()->getSize() > 32) return false;
    return program->getLanguage()->getProcessor().getName() == "x86";
}

bool X86FunctionPurgeAnalyzer::added(Program* program, const AddressSetView& set,
                                      TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    auto* funcMgr = program->getFunctionManager();
    auto* listing = program->getListing();
    if (!funcMgr || !listing) return false;

    FunctionIterator funcIter = funcMgr->getFunctions(set);
    if (monitor) {
        monitor->initialize(static_cast<int>(funcIter.remaining()));
    }

    int count = 0;
    int purgedCount = 0;

    while (funcIter.hasNext()) {
        if (monitor && monitor->isCancelled()) break;
        if (monitor) monitor->setProgress(++count);

        Function* func = funcIter.next();
        if (!func) continue;

        monitor->setMessage("Analyzing purge: " + func->getName());

        std::vector<Instruction*> instructions = listing->getInstructions(func->getBody());
        bool foundRet = false;
        int purgeSize = -1;

        for (Instruction* instr : instructions) {
            if (monitor && monitor->isCancelled()) break;

            std::string mnemonic = instr->getMnemonicString();
            if (mnemonic != "RET" && mnemonic != "RETF" && mnemonic != "RETN")
                continue;

            foundRet = true;
            std::vector<Scalar*> scalars = instr->getOperandScalars(0);
            if (!scalars.empty()) {
                int sz = static_cast<int>(scalars[0]->getUnsignedValue());
                if (purgeSize < 0) {
                    purgeSize = sz;
                } else if (purgeSize != sz) {
                    purgeSize = -2;
                }
            }
        }

        if (purgeSize > 0) {
            StackFrame* stackFrame = func->getStackFrame();
            if (stackFrame) {
                stackFrame->setPurgeSize(purgeSize);
                purgedCount++;
            }
        } else if (purgeSize == 0 && foundRet) {
            StackFrame* stackFrame = func->getStackFrame();
            if (stackFrame) {
                stackFrame->setPurgeSize(0);
            }
        }
    }

    if (monitor) {
        monitor->setMessage(getName() + ": Set purge for " +
                            std::to_string(purgedCount) + " functions");
    }

    return true;
}

} // namespace ghidra
