#include <ghidra/ContextEvaluatorAdapter.h>

namespace ghidra {

bool ContextEvaluatorAdapter::evaluateContextBefore(VarnodeContext* context, Instruction* instr) {
    return false;
}

bool ContextEvaluatorAdapter::evaluateContext(VarnodeContext* context, Instruction* instr) {
    return false;
}

Address ContextEvaluatorAdapter::evaluateConstant(VarnodeContext* context, Instruction* instr,
        int pcodeop, const Address& constant, int size, DataType* dataType,
        const RefType* refType) {
    return Address();
}

bool ContextEvaluatorAdapter::evaluateReference(VarnodeContext* context, Instruction* instr,
        int pcodeop, const Address& address, int size, DataType* dataType,
        const RefType* refType) {
    return false;
}

bool ContextEvaluatorAdapter::evaluateDestination(VarnodeContext* context,
        Instruction* instruction) {
    return false;
}

bool ContextEvaluatorAdapter::evaluateReturn(const Varnode* retVN, VarnodeContext* context,
        Instruction* instruction) {
    return false;
}

int64_t* ContextEvaluatorAdapter::unknownValue(VarnodeContext* context, Instruction* instruction,
        const Varnode* node) {
    return nullptr;
}

bool ContextEvaluatorAdapter::followFalseConditionalBranches() {
    return true;
}

bool ContextEvaluatorAdapter::evaluateSymbolicReference(VarnodeContext* context,
        Instruction* instr, const Address& address) {
    return false;
}

bool ContextEvaluatorAdapter::allowAccess(VarnodeContext* context, const Address& addr) {
    return false;
}

} // namespace ghidra
