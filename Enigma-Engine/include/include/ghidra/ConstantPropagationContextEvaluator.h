#pragma once

#include <ghidra/ContextEvaluatorAdapter.h>
#include <ghidra/AddressSet.h>
#include <ghidra/DataType.h>

namespace ghidra {

class TaskMonitor;

class ConstantPropagationContextEvaluator : public ContextEvaluatorAdapter {
public:
    ConstantPropagationContextEvaluator(TaskMonitor* monitor);
    ConstantPropagationContextEvaluator(TaskMonitor* monitor, bool trustMemoryWrite);
    ConstantPropagationContextEvaluator(TaskMonitor* monitor, bool trustWriteMemOption,
                                         long minStoreLoadRefAddress,
                                         long minSpeculativeRefAddress,
                                         long maxSpeculativeRefAddress);

    ConstantPropagationContextEvaluator* setTrustWritableMemory(bool trustWriteableMemOption);
    ConstantPropagationContextEvaluator* setMinSpeculativeOffset(long minSpeculativeRefAddress);
    ConstantPropagationContextEvaluator* setMaxSpeculativeOffset(long maxSpeculativeRefAddress);
    ConstantPropagationContextEvaluator* setMinStoreLoadOffset(long minStoreLoadRefAddress);
    ConstantPropagationContextEvaluator* setCreateComplexDataFromPointers(bool doCreateData);

    AddressSet* getDestinationSet();

    Address evaluateConstant(VarnodeContext* context, Instruction* instr, int pcodeop,
                             const Address& constant, int size, DataType* dataType,
                             const RefType* refType) override;
    bool evaluateReference(VarnodeContext* context, Instruction* instr, int pcodeop,
                           const Address& address, int size, DataType* dataType,
                           const RefType* refType) override;
    bool evaluateDestination(VarnodeContext* context, Instruction* instruction) override;
    bool allowAccess(VarnodeContext* context, const Address& addr) override;

private:
    static constexpr int MAX_UNICODE_STRING_LEN = 200;
    static constexpr int MAX_CHAR_STRING_LEN = 100;

    AddressSet destSet;
    bool trustMemoryWrite = false;
    bool createDataFromPointers = false;
    long minStoreLoadOffset = 4;
    long minSpeculativeOffset = 1024;
    long maxSpeculativeOffset = 256;

    TaskMonitor* monitor;
};

} // namespace ghidra
