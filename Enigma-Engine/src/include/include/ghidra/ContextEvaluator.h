#pragma once

#include <ghidra/Address.h>
#include <ghidra/DataType.h>
#include <ghidra/Instruction.h>
#include <ghidra/RefType.h>
#include <ghidra/Varnode.h>
#include <cstdint>

namespace ghidra {

class VarnodeContext;

class ContextEvaluator {
public:
    virtual ~ContextEvaluator() = default;

    virtual bool evaluateContextBefore(VarnodeContext* context, Instruction* instr) = 0;

    virtual bool evaluateContext(VarnodeContext* context, Instruction* instr) = 0;

    virtual bool evaluateReference(VarnodeContext* context, Instruction* instr, int pcodeop,
                                   const Address& address, int size, DataType* dataType,
                                   const RefType* refType) = 0;

    virtual Address evaluateConstant(VarnodeContext* context, Instruction* instr, int pcodeop,
                                     const Address& constant, int size, DataType* dataType,
                                     const RefType* refType) = 0;

    virtual bool evaluateDestination(VarnodeContext* context, Instruction* instruction) = 0;

    virtual bool evaluateReturn(const Varnode* retVN, VarnodeContext* context,
                                Instruction* instruction) = 0;

    virtual int64_t* unknownValue(VarnodeContext* context, Instruction* instruction,
                                  const Varnode* node) = 0;

    virtual bool followFalseConditionalBranches() = 0;

    virtual bool evaluateSymbolicReference(VarnodeContext* context, Instruction* instr,
                                           const Address& address) = 0;

    virtual bool allowAccess(VarnodeContext* context, const Address& addr) = 0;
};

} // namespace ghidra
