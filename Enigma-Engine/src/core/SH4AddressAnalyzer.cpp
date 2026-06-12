#include <ghidra/SH4AddressAnalyzer.h>
#include <ghidra/ConstantPropagationContextEvaluator.h>
#include <ghidra/SymbolicPropogator.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/PcodeOp.h>
#include <ghidra/Varnode.h>
#include <ghidra/VarnodeContext.h>
#include <ghidra/Register.h>
#include <ghidra/RegisterValue.h>
#include <ghidra/ProgramContext.h>
#include <ghidra/TaskMonitor.h>

namespace ghidra {

namespace {

class SH4PropagationEvaluator : public ConstantPropagationContextEvaluator {
public:
    SH4PropagationEvaluator(TaskMonitor* mon, bool trustWriteMem, SH4AddressAnalyzer* analyzer,
                             Program* program)
        : ConstantPropagationContextEvaluator(mon, trustWriteMem),
          analyzer_(analyzer), program_(program), monitor_(mon) {}

    bool evaluateReference(VarnodeContext* context, Instruction* instr, int pcodeop,
                            const Address& address, int size, DataType* dataType,
                            const RefType* refType) override {
        if (address.isExternalAddress()) return true;

        if (refType->isCall() && instr->getFlowType()->isCall()) {
            analyzer_->propagateR12ToCall(program_, context, address);
        }

        bool doRef = ConstantPropagationContextEvaluator::evaluateReference(
            context, instr, pcodeop, address, size, dataType, refType);
        if (!doRef) return false;

        if (analyzer_->checkComputedRelativeBranch(program_, monitor_, instr, address,
                                                     refType, pcodeop)) {
            return false;
        }
        return doRef;
    }

private:
    SH4AddressAnalyzer* analyzer_;
    Program* program_;
    TaskMonitor* monitor_;
};

} // anonymous namespace

SH4AddressAnalyzer::SH4AddressAnalyzer()
    : ConstantPropagationAnalyzer(PROCESSOR_NAME) {
}

bool SH4AddressAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getLanguage()) return false;
    if (program->getLanguage()->getProcessor().getName() != PROCESSOR_NAME) return false;
    SH4AddressAnalyzer* self = const_cast<SH4AddressAnalyzer*>(this);
    self->r12_ = program->getRegister("r12");
    return r12_ != nullptr;
}

void SH4AddressAnalyzer::registerOptions(Options& options, Program* program) {
    ConstantPropagationAnalyzer::registerOptions(options, program);
    options.registerBool(OPT_PROPAGATE_R12, propagateR12_,
                         "R12 can be used as a pointer to the GOT table. "
                         "If it is a constant value propagate the value into called functions.");
}

void SH4AddressAnalyzer::optionsChanged(Options& options, Program* program) {
    ConstantPropagationAnalyzer::optionsChanged(options, program);
    propagateR12_ = options.getBool(OPT_PROPAGATE_R12);
}

AddressSet SH4AddressAnalyzer::flowConstants(Program* program, const Address& flowStart,
                                              const AddressSetView* flowSet,
                                              SymbolicPropogator* symEval,
                                              TaskMonitor* monitor) {
    SH4PropagationEvaluator eval(monitor, trustWriteMemOption, this, program);
    eval.setTrustWritableMemory(trustWriteMemOption)
        ->setMinSpeculativeOffset(minSpeculativeRefAddress)
        ->setMaxSpeculativeOffset(maxSpeculativeRefAddress)
        ->setMinStoreLoadOffset(minStoreLoadRefAddress)
        ->setCreateComplexDataFromPointers(createComplexDataFromPointers);

    return symEval->flowConstants(flowStart, nullptr, &eval, true, monitor);
}

bool SH4AddressAnalyzer::checkComputedRelativeBranch(Program* program, TaskMonitor* monitor,
                                                       Instruction* instr,
                                                       const Address& address,
                                                       const RefType* refType, int pcodeop) {
    if (pcodeop == PcodeOp::UNIMPLEMENTED) return false;
    if (!refType->isComputed()) return false;

    const std::string& mnemonic = instr->getMnemonicString();
    if (mnemonic == "bsrf" || mnemonic == "braf") {
        instr->addOperandReference(0, address, refType, SourceType::ANALYSIS);
        // Disassembler calls blocked - would need Disassembler + AutoAnalysisManager
        return true;
    }
    return false;
}

void SH4AddressAnalyzer::propagateR12ToCall(Program* program, VarnodeContext* context,
                                              const Address& address) {
    if (!propagateR12_) return;

    RegisterValue* registerValue = context->getRegisterValue(r12_);
    if (registerValue) {
        uint64_t value = registerValue->getUnsignedOffset();
        try {
            program->getProgramContext()->setValue(r12_, value, address, address);
        } catch (...) {
            // ContextChangeException
        }
    }
}

} // namespace ghidra
