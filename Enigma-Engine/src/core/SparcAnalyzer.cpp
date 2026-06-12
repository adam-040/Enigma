#include <ghidra/SparcAnalyzer.h>
#include <ghidra/ConstantPropagationContextEvaluator.h>
#include <ghidra/SymbolicPropogator.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/PcodeOp.h>
#include <ghidra/Varnode.h>
#include <ghidra/VarnodeContext.h>
#include <ghidra/Register.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/AnalysisPriority.h>

namespace ghidra {

namespace {

class SparcPropagationEvaluator : public ConstantPropagationContextEvaluator {
public:
    SparcPropagationEvaluator(TaskMonitor* monitor, bool trustWriteMem, Program* program,
                               Register* linkReg, bool o7Check)
        : ConstantPropagationContextEvaluator(monitor, trustWriteMem),
          program_(program), linkReg_(linkReg), o7Check_(o7Check) {}

    bool evaluateContext(VarnodeContext* context, Instruction* instr) override {
        FlowType* ftype = instr->getFlowType();
        if (!ftype) return false;

        if (o7Check_ && ftype->isCall()) {
            Address fallAddr = instr->getFallThrough();
            if (!fallAddr.isValid()) return false;

            Instruction* delayInstr = program_->getListing()->getInstructionAfter(
                instr->getMaxAddress());
            if (!delayInstr) return false;

            for (PcodeOp* pcodeOp : delayInstr->getPcode()) {
                Varnode* output = pcodeOp->getOutput();
                if (!output) continue;
                if (!(*output == *(context->getRegisterVarnode(linkReg_)))) continue;

                Varnode* input = pcodeOp->getInput(0);
                if (input && input->isConstant()) continue; // just assigning return value

                instr->setFallThrough(Address()); // clear fallthrough
                Instruction* fallInstr = program_->getListing()->getInstructionAt(fallAddr);
                if (!fallInstr) return false;

                if (!program_->getReferenceManager()->getReferencesTo(fallAddr).empty()) {
                    return false;
                }

                // ClearFlowAndRepairCmd would go here - not available
                // Simplified: just clear the fallthrough
                break;
            }
        }
        return false;
    }

    bool evaluateDestination(VarnodeContext* context, Instruction* instruction) override {
        FlowType* flowType = instruction->getFlowType();
        if (!flowType || !flowType->isJump()) return false;

        auto refs = instruction->getReferencesFrom();
        bool hasOnlyData = true;
        for (Reference* ref : refs) {
            if (ref && ref->getReferenceType() && !ref->getReferenceType()->isData()) {
                hasOnlyData = false;
                break;
            }
        }
        if (refs.empty() || hasOnlyData) {
            getDestinationSet()->addRange(instruction->getAddress(), instruction->getAddress());
        }
        return false;
    }

private:
    Program* program_;
    Register* linkReg_;
    bool o7Check_;
};

} // anonymous namespace

SparcAnalyzer::SparcAnalyzer()
    : ConstantPropagationAnalyzer(PROCESSOR_NAME) {
    setPriority(AnalysisPriority::FUNCTION_ANALYSIS.after());
}

bool SparcAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getLanguage()) return false;
    return program->getLanguage()->getProcessor().getName() == PROCESSOR_NAME;
}

void SparcAnalyzer::registerOptions(Options& options, Program* program) {
    ConstantPropagationAnalyzer::registerOptions(options, program);
    options.registerBool(O7_CALLRETURN_NAME, o7CallReturnAnalysis_,
                         "Turn on check for setting of o7 return link register in delay slot of all calls");
}

void SparcAnalyzer::optionsChanged(Options& options, Program* program) {
    ConstantPropagationAnalyzer::optionsChanged(options, program);
    o7CallReturnAnalysis_ = options.getBool(O7_CALLRETURN_NAME);
}

AddressSet SparcAnalyzer::flowConstants(Program* program, const Address& flowStart,
                                         const AddressSetView* flowSet,
                                         SymbolicPropogator* symEval,
                                         TaskMonitor* monitor) {
    Register* linkReg = program->getRegister("o7");

    SparcPropagationEvaluator eval(monitor, trustWriteMemOption, program,
                                    linkReg, o7CallReturnAnalysis_);
    eval.setTrustWritableMemory(trustWriteMemOption)
        ->setMinSpeculativeOffset(minSpeculativeRefAddress)
        ->setMaxSpeculativeOffset(maxSpeculativeRefAddress)
        ->setMinStoreLoadOffset(minStoreLoadRefAddress)
        ->setCreateComplexDataFromPointers(createComplexDataFromPointers);

    return symEval->flowConstants(flowStart, flowSet, &eval, true, monitor);
}

} // namespace ghidra
