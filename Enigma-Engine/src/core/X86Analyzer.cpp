#include <ghidra/X86Analyzer.h>
#include <ghidra/ConstantPropagationContextEvaluator.h>
#include <ghidra/SymbolicPropogator.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Register.h>
#include <ghidra/VarnodeContext.h>
#include <ghidra/TaskMonitor.h>

namespace ghidra {

namespace {

class X86PropagationEvaluator : public ConstantPropagationContextEvaluator {
public:
    X86PropagationEvaluator(TaskMonitor* monitor, bool trustWriteMem, Program* program)
        : ConstantPropagationContextEvaluator(monitor, trustWriteMem), program_(program) {}

    bool evaluateContext(VarnodeContext* context, Instruction* instr) override {
        const std::string& mnemonic = instr->getMnemonicString();
        if (mnemonic == "LEA") {
            auto regs = instr->getOperandRegisters(0);
            if (!regs.empty()) {
                Register* reg = regs[0];
                uint64_t val = context->getValue(reg, false);
                if (val != 0 || context->getValue(reg, true) != 0) {
                    int64_t lval = static_cast<int64_t>(val);
                    AddressSpace* space = const_cast<AddressSpace*>(instr->getMinAddress().getAddressSpace());
                    Address refAddr(space, lval);
                    if ((lval > 4096 || lval < 0) && program_->getMemory()->getBlock(refAddr) != nullptr) {
                        if (instr->getOperandReferences(1).empty()) {
                            instr->addOperandReference(1, refAddr, &RefTypes::DATA,
                                                        SourceType::ANALYSIS);
                        }
                    }
                }
            }
        }
        return false;
    }

    bool evaluateReference(VarnodeContext* context, Instruction* instr, int pcodeop,
                            const Address& address, int size, DataType* dataType,
                            const RefType* refType) override {
        if (refType->isFlow() &&
            program_->getMemory()->getBlock(address) == nullptr &&
            !address.isExternalAddress()) {
            return false;
        }
        return ConstantPropagationContextEvaluator::evaluateReference(
            context, instr, pcodeop, address, size, dataType, refType);
    }

private:
    Program* program_;
};

} // anonymous namespace

X86Analyzer::X86Analyzer()
    : ConstantPropagationAnalyzer("x86") {
}

bool X86Analyzer::canAnalyze(Program* program) const {
    if (!program || !program->getLanguage()) return false;
    return program->getLanguage()->getProcessor().getName() == "x86";
}

AddressSet X86Analyzer::flowConstants(Program* program, const Address& flowStart,
                                       const AddressSetView* flowSet,
                                       SymbolicPropogator* symEval,
                                       TaskMonitor* monitor) {
    X86PropagationEvaluator eval(monitor, trustWriteMemOption, program);
    eval.setTrustWritableMemory(trustWriteMemOption);
    eval.setMinSpeculativeOffset(minSpeculativeRefAddress);
    eval.setMaxSpeculativeOffset(maxSpeculativeRefAddress);
    eval.setMinStoreLoadOffset(minStoreLoadRefAddress);
    eval.setCreateComplexDataFromPointers(createComplexDataFromPointers);

    return symEval->flowConstants(flowStart, flowSet, &eval, true, monitor);
}

} // namespace ghidra
