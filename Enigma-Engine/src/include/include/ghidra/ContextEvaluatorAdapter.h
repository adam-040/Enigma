#pragma once

#include <ghidra/ContextEvaluator.h>

namespace ghidra {

class ContextEvaluatorAdapter : public ContextEvaluator {
public:
    bool evaluateContextBefore(VarnodeContext* context, Instruction* instr) override;
    bool evaluateContext(VarnodeContext* context, Instruction* instr) override;
    Address evaluateConstant(VarnodeContext* context, Instruction* instr, int pcodeop,
                             const Address& constant, int size, DataType* dataType,
                             const RefType* refType) override;
    bool evaluateReference(VarnodeContext* context, Instruction* instr, int pcodeop,
                           const Address& address, int size, DataType* dataType,
                           const RefType* refType) override;
    bool evaluateDestination(VarnodeContext* context, Instruction* instruction) override;
    bool evaluateReturn(const Varnode* retVN, VarnodeContext* context,
                        Instruction* instruction) override;
    int64_t* unknownValue(VarnodeContext* context, Instruction* instruction,
                          const Varnode* node) override;
    bool followFalseConditionalBranches() override;
    bool evaluateSymbolicReference(VarnodeContext* context, Instruction* instr,
                                   const Address& address) override;
    bool allowAccess(VarnodeContext* context, const Address& addr) override;
};

} // namespace ghidra
