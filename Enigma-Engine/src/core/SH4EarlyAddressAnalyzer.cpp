#include <ghidra/SH4EarlyAddressAnalyzer.h>
#include <ghidra/ConstantPropagationContextEvaluator.h>
#include <ghidra/SymbolicPropogator.h>
#include <ghidra/Program.h>
#include <ghidra/Instruction.h>
#include <ghidra/VarnodeContext.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/AnalysisPriority.h>

namespace ghidra {

namespace {

class SH4EarlyEvaluator : public ConstantPropagationContextEvaluator {
public:
    SH4EarlyEvaluator(TaskMonitor* mon, bool trustWriteMem, SH4AddressAnalyzer* analyzer,
                       Program* program)
        : ConstantPropagationContextEvaluator(mon, trustWriteMem),
          analyzer_(analyzer), program_(program), monitor_(mon) {}

    bool evaluateReference(VarnodeContext* context, Instruction* instr, int pcodeop,
                            const Address& address, int size, DataType* dataType,
                            const RefType* refType) override {
        if (refType->isFlow()) {
            if (address.isExternalAddress()) return true;

            if (instr->getFlowType()->isCall()) {
                analyzer_->propagateR12ToCall(program_, context, address);
            }

            if (refType->isComputed()) {
                bool doRef = ConstantPropagationContextEvaluator::evaluateReference(
                    context, instr, pcodeop, address, size, dataType, refType);
                if (!doRef) return false;
                if (analyzer_->checkComputedRelativeBranch(program_, monitor_, instr, address,
                                                           refType, pcodeop)) {
                    return false;
                }
                return doRef;
            }
        }
        return false;
    }

private:
    SH4AddressAnalyzer* analyzer_;
    Program* program_;
    TaskMonitor* monitor_;
};

} // anonymous namespace

SH4EarlyAddressAnalyzer::SH4EarlyAddressAnalyzer()
    : SH4AddressAnalyzer() {
    setPriority(AnalysisPriority::DISASSEMBLY);
}

AddressSet SH4EarlyAddressAnalyzer::flowConstants(Program* program, const Address& flowStart,
                                                   const AddressSetView* flowSet,
                                                   SymbolicPropogator* symEval,
                                                   TaskMonitor* monitor) {
    SH4EarlyEvaluator eval(monitor, trustWriteMemOption, this, program);
    eval.setTrustWritableMemory(trustWriteMemOption)
        ->setMinSpeculativeOffset(minSpeculativeRefAddress)
        ->setMaxSpeculativeOffset(maxSpeculativeRefAddress)
        ->setMinStoreLoadOffset(minStoreLoadRefAddress)
        ->setCreateComplexDataFromPointers(createComplexDataFromPointers);

    return symEval->flowConstants(flowStart, nullptr, &eval, true, monitor);
}

} // namespace ghidra
