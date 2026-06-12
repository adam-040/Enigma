#include <ghidra/StackVariableAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/Scalar.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/FunctionIterator.h>
#include <ghidra/Function.h>
#include <ghidra/StackFrame.h>
#include <ghidra/Variable.h>
#include <ghidra/AddressSet.h>
#include <ghidra/Options.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>

namespace ghidra {

StackVariableAnalyzer::StackVariableAnalyzer()
    : AbstractAnalyzer("Stack",
                       "Creates stack variables for a function.",
                       AnalyzerType::FUNCTION_ANALYZER) {
    setPriority(AnalysisPriority::DATA_TYPE_PROPOGATION.after().after().after());
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis();
}

bool StackVariableAnalyzer::added(Program* program, const AddressSetView& set,
                                   TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    auto* funcMgr = program->getFunctionManager();
    auto* listing = program->getListing();
    if (!funcMgr || !listing) return false;

    FunctionIterator funcIter = funcMgr->getFunctions(set);
    if (monitor) {
        monitor->initialize(static_cast<int4>(funcIter.remaining()));
        monitor->setMessage(getName());
    }

    int count = 0;
    while (funcIter.hasNext()) {
        if (monitor && monitor->isCancelled()) break;
        if (monitor) monitor->setProgress(++count);

        Function* func = funcIter.next();
        if (!func) continue;

        StackFrame* frame = func->getStackFrame();
        if (!frame) continue;

        int frameSize = frame->getFrameSize();
        if (frameSize <= 0) continue;

        const AddressSet& body = func->getBody();
        if (body.isEmpty()) continue;

        auto instructions = listing->getInstructions(body);
        for (Instruction* instr : instructions) {
            if (!instr) continue;
            if (monitor && monitor->isCancelled()) break;

            for (int op = 0; op < instr->getNumOperands(); ++op) {
                auto scalars = instr->getOperandScalars(op);
                for (Scalar* scalar : scalars) {
                    if (!scalar) continue;
                    int64_t value = static_cast<int64_t>(scalar->getSignedValue());

                    int paramOffset = frame->getParameterOffset();
                    int localSize = frame->getLocalSize();
                    int paramSize = frame->getParameterSize();

                    bool isStackRef = false;
                    if (value < 0 && -value <= localSize) isStackRef = true;
                    else if (value >= 0 && value < paramSize) isStackRef = true;
                    else if (value >= paramOffset && value < paramOffset + paramSize) isStackRef = true;

                    if (isStackRef) {
                        bool isLocal = (value < 0);
                        if ((isLocal && doCreateLocalStackVars_) ||
                            (!isLocal && doCreateStackParams_)) {
                            if (!frame->getVariableContaining(static_cast<int>(value))) {
                                frame->createVariable("", static_cast<int>(value),
                                                       nullptr, SourceType::ANALYSIS);
                            }
                        }
                    }
                }
            }
        }
    }

    return true;
}

void StackVariableAnalyzer::registerOptions(Options& options, Program* program) {
    options.registerBool("Create Local Variables", doCreateLocalStackVars_,
                         "Create Function Local stack variables and references");
    options.registerBool("Create Param Variables", doCreateStackParams_,
                         "Create Function Parameter stack variables and references");
}

void StackVariableAnalyzer::optionsChanged(Options& options, Program* program) {
    if (options.hasOption("Create Local Variables"))
        doCreateLocalStackVars_ = options.getBool("Create Local Variables");
    if (options.hasOption("Create Param Variables"))
        doCreateStackParams_ = options.getBool("Create Param Variables");
}

} // namespace ghidra
