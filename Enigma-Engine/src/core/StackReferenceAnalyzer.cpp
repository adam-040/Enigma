#include <ghidra/StackReferenceAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/Scalar.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/StackFrame.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/RefTypeFactory.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/Msg.h>

namespace ghidra {

StackReferenceAnalyzer::StackReferenceAnalyzer()
    : AbstractAnalyzer("Stack Reference Analyzer",
                       "Creates stack references from instruction operands that refer to stack offsets.",
                       AnalyzerType::INSTRUCTION_ANALYZER) {
    setPriority(AnalysisPriority::REFERENCE_ANALYSIS);
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

bool StackReferenceAnalyzer::canAnalyze(Program* program) const {
    return program != nullptr;
}

bool StackReferenceAnalyzer::getDefaultEnablement(Program* program) const {
    return program != nullptr;
}

bool StackReferenceAnalyzer::added(Program* program, const AddressSetView& set,
                                    TaskMonitor* monitor, MessageLog& log) {
    if (!program || !monitor) return false;
    monitor->setMessage("Creating stack references...");

    Listing* listing = program->getListing();
    FunctionManager* funcMgr = program->getFunctionManager();
    ReferenceManager* refMgr = program->getReferenceManager();
    if (!listing || !funcMgr || !refMgr) return true;

    auto instructions = listing->getInstructions(set);
    int count = 0;
    for (Instruction* instr : instructions) {
        if (monitor->isCancelled()) break;

        Function* func = funcMgr->getFunctionContaining(instr->getMinAddress());
        if (!func) continue;

        StackFrame* frame = func->getStackFrame();
        if (!frame) continue;

        int localSize = frame->getLocalSize();
        int paramOffset = frame->getParameterOffset();
        int stackSize = frame->getFrameSize();

        for (int i = 0; i < instr->getNumOperands(); ++i) {
            auto scalars = instr->getOperandScalars(i);
            for (Scalar* scalar : scalars) {
                long val = static_cast<long>(scalar->getSignedValue());
                if (val >= 0) continue;
                int stackOffset = static_cast<int>(val);
                if (stackOffset < -stackSize || stackOffset >= 0) continue;

                if (!instr->getOperandReferences(i).empty()) continue;

                bool isLocal = (stackOffset <= localSize);
                const RefType* type = isLocal ? &RefTypes::READ : &RefTypes::READ;
                refMgr->addStackReference(instr->getMinAddress(), i, stackOffset, type, SourceType::ANALYSIS);
                ++count;
            }
        }
    }

    if (count > 0) {
        Msg::info(getName(), "Created " + std::to_string(count) + " stack references.");
    }
    return true;
}

} // namespace ghidra
