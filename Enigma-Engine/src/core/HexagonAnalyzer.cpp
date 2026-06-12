#include <ghidra/HexagonAnalyzer.h>
#include <ghidra/ConstantPropagationContextEvaluator.h>
#include <ghidra/SymbolicPropogator.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/Register.h>
#include <ghidra/Scalar.h>
#include <ghidra/VarnodeContext.h>
#include <ghidra/Varnode.h>
#include <ghidra/TaskMonitor.h>

namespace ghidra {

namespace {

class HexagonPropagationEvaluator : public ConstantPropagationContextEvaluator {
public:
    HexagonPropagationEvaluator(TaskMonitor* monitor, bool trustWriteMem, Program* program,
                                 Register* r25, Register* lr, Register* lrNew)
        : ConstantPropagationContextEvaluator(monitor, trustWriteMem),
          program_(program), r25_(r25), lr_(lr), lrNew_(lrNew) {}

    bool evaluateContext(VarnodeContext* context, Instruction* instr) override {
        FlowType* ftype = instr->getFlowType();
        if (!ftype) return false;

        if (ftype->isComputed() && ftype->isJump()) {
            // Check if destination is LR or LR.new
            Varnode* destVal = nullptr;
            auto flows = instr->getFlows();
            if (!flows.empty()) {
                destVal = flows[0];
            }
            if (destVal && isLinkRegister(context, destVal)) {
                instr->setFlowOverride(FlowOverride::RETURN);
            }
        }
        return false;
    }

    bool evaluateReference(VarnodeContext* context, Instruction* instr, int pcodeop,
                            const Address& address, int size, DataType* dataType,
                            const RefType* refType) override {
        if (address.isExternalAddress()) {
            return true;
        }

        if (!ConstantPropagationContextEvaluator::evaluateReference(
                context, instr, pcodeop, address, size, dataType, refType)) {
            return false;
        }

        if (refType->isData()) {
            if (refType->isWrite()) {
                instr->addOperandReference(0, address, refType, SourceType::ANALYSIS);
                return false;
            } else if (refType->isRead()) {
                instr->addOperandReference(1, address, refType, SourceType::ANALYSIS);
                return false;
            }
        }

        return markupParallelInstruction(instr, refType, address);
    }

    bool evaluateDestination(VarnodeContext* context, Instruction* instruction) override {
        FlowType* flowType = instruction->getFlowType();
        if (!flowType || !flowType->isJump()) return false;

        auto refs = instruction->getReferencesFrom();
        bool hasOnlyData = true;
        for (Reference* ref : refs) {
            if (ref && !ref->getReferenceType()->isData()) {
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
    bool isLinkRegister(VarnodeContext* context, Varnode* destVal) {
        if (destVal->isRegister()) {
            Address destAddr = destVal->getAddress();
            Address lrAddr = lr_ ? lr_->getAddress() : Address();
            Address lrNewAddr = lrNew_ ? lrNew_->getAddress() : Address();
            return (lrAddr.isValid() && destAddr == lrAddr) ||
                   (lrNewAddr.isValid() && destAddr == lrNewAddr);
        } else if (context->isSymbol(destVal) && destVal->getAddress().getOffset() == 0) {
            std::string spaceName = destVal->getAddress().getAddressSpace()->getName();
            return (lr_ && spaceName == lr_->getName()) ||
                   (lrNew_ && spaceName == lrNew_->getName());
        }
        return false;
    }

    bool markupParallelInstruction(Instruction* instr, const RefType* refType,
                                    const Address& address) {
        Instruction* prevInst = instr;
        for (int count = 0; count < 5; count++) {
            Address fallFrom = prevInst->getFallFrom();
            if (!fallFrom.isValid()) break;

            prevInst = program_->getListing()->getInstructionAt(fallFrom);
            if (!prevInst) break;

            int numOps = prevInst->getNumOperands();
            for (int i = 0; i < numOps; i++) {
                auto scalars = prevInst->getOperandScalars(i);
                for (Scalar* scalar : scalars) {
                    if (scalar && scalar->getUnsignedValue() ==
                                   static_cast<uint64_t>(address.getOffset())) {
                        prevInst->addOperandReference(i, address, refType, SourceType::ANALYSIS);
                        return false;
                    }
                }
            }
        }
        return true;
    }

    Program* program_;
    Register* r25_;
    Register* lr_;
    Register* lrNew_;
};

} // anonymous namespace

HexagonAnalyzer::HexagonAnalyzer()
    : ConstantPropagationAnalyzer("Hexagon") {
    setPriority(AnalysisPriority::CODE_ANALYSIS.after());
}

bool HexagonAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getLanguage()) return false;
    if (program->getLanguage()->getProcessor().getName() != "Hexagon") return false;

    // Cache registers
    HexagonAnalyzer* self = const_cast<HexagonAnalyzer*>(this);
    self->r25Register_ = program->getRegister("R25");
    self->lrRegister_ = program->getRegister("LR");
    self->lrNewRegister_ = program->getRegister("LR.new");

    return r25Register_ && lrRegister_ && lrNewRegister_;
}

AddressSet HexagonAnalyzer::flowConstants(Program* program, const Address& flowStart,
                                           const AddressSetView* flowSet,
                                           SymbolicPropogator* symEval,
                                           TaskMonitor* monitor) {
    HexagonPropagationEvaluator eval(monitor, trustWriteMemOption, program,
                                      r25Register_, lrRegister_, lrNewRegister_);
    eval.setTrustWritableMemory(trustWriteMemOption)
        ->setMinSpeculativeOffset(minSpeculativeRefAddress)
        ->setMaxSpeculativeOffset(maxSpeculativeRefAddress)
        ->setMinStoreLoadOffset(minStoreLoadRefAddress)
        ->setCreateComplexDataFromPointers(createComplexDataFromPointers);

    return symEval->flowConstants(flowStart, flowSet, &eval, true, monitor);
}

} // namespace ghidra
