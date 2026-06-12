#include <ghidra/LoongsonAnalyzer.h>
#include <ghidra/ConstantPropagationContextEvaluator.h>
#include <ghidra/SymbolicPropogator.h>
#include <ghidra/Program.h>
#include <ghidra/Register.h>
#include <ghidra/VarnodeContext.h>
#include <ghidra/Varnode.h>
#include <ghidra/FlowOverride.h>
#include <ghidra/TaskMonitor.h>

namespace ghidra {

namespace {

class LoongsonPropagationEvaluator : public ConstantPropagationContextEvaluator {
public:
    LoongsonPropagationEvaluator(TaskMonitor* monitor, bool trustWriteMem, Program* program,
                                  Register* linkReg, const Address& flowStart)
        : ConstantPropagationContextEvaluator(monitor, trustWriteMem),
          program_(program), linkReg_(linkReg), flowStart_(flowStart) {}

    bool evaluateReturn(const Varnode* retVN, VarnodeContext* context,
                         Instruction* instruction) override {
        if (instruction->getFlowOverride() != FlowOverride::NONE) return false;

        if (retVN && context->isConstant(const_cast<Varnode*>(retVN))) {
            long offset = retVN->getOffset();
            if (offset > 3 && offset != -1) {
                instruction->setFlowOverride(FlowOverride::CALL_RETURN);
                return false;
            }
        }
        return false;
    }

private:
    Program* program_;
    Register* linkReg_;
    Address flowStart_;
};

} // anonymous namespace

LoongsonAnalyzer::LoongsonAnalyzer()
    : ConstantPropagationAnalyzer(PROCESSOR_NAME) {
}

bool LoongsonAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getLanguage()) return false;
    if (program->getLanguage()->getProcessor().getName() != PROCESSOR_NAME) return false;
    LoongsonAnalyzer* self = const_cast<LoongsonAnalyzer*>(this);
    self->linkRegister_ = program->getRegister("ra");
    return linkRegister_ != nullptr;
}

AddressSet LoongsonAnalyzer::flowConstants(Program* program, const Address& flowStart,
                                            const AddressSetView* flowSet,
                                            SymbolicPropogator* symEval,
                                            TaskMonitor* monitor) {
    LoongsonPropagationEvaluator eval(monitor, trustWriteMemOption, program,
                                       linkRegister_, flowStart);
    eval.setTrustWritableMemory(trustWriteMemOption)
        ->setMinSpeculativeOffset(minSpeculativeRefAddress)
        ->setMaxSpeculativeOffset(maxSpeculativeRefAddress)
        ->setMinStoreLoadOffset(minStoreLoadRefAddress)
        ->setCreateComplexDataFromPointers(createComplexDataFromPointers);

    return symEval->flowConstants(flowStart, flowSet, &eval, true, monitor);
}

} // namespace ghidra
