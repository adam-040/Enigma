#include <ghidra/ConstantPropagationContextEvaluator.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/Instruction.h>
#include <ghidra/Listing.h>
#include <ghidra/Memory.h>
#include <ghidra/PcodeOp.h>
#include <ghidra/Program.h>
#include <ghidra/RefType.h>
#include <ghidra/VarnodeContext.h>
#include <cstdlib>

namespace ghidra {

namespace {
    int64_t maxOffsetForSpaceSize(int size) {
        if (size >= 64) return -1;
        return (1LL << size) - 1;
    }
}

ConstantPropagationContextEvaluator::ConstantPropagationContextEvaluator(TaskMonitor* monitor_)
    : monitor(monitor_) {}

ConstantPropagationContextEvaluator::ConstantPropagationContextEvaluator(
        TaskMonitor* monitor_, bool trustMemoryWrite_)
    : monitor(monitor_), trustMemoryWrite(trustMemoryWrite_) {}

ConstantPropagationContextEvaluator::ConstantPropagationContextEvaluator(
        TaskMonitor* monitor_, bool trustWriteMemOption,
        long minStoreLoadRefAddress, long minSpeculativeRefAddress,
        long maxSpeculativeRefAddress)
    : monitor(monitor_), trustMemoryWrite(trustWriteMemOption),
      minStoreLoadOffset(minStoreLoadRefAddress),
      minSpeculativeOffset(minSpeculativeRefAddress),
      maxSpeculativeOffset(maxSpeculativeRefAddress) {}

ConstantPropagationContextEvaluator* ConstantPropagationContextEvaluator::setTrustWritableMemory(
        bool trustWriteableMemOption) {
    trustMemoryWrite = trustWriteableMemOption;
    return this;
}

ConstantPropagationContextEvaluator* ConstantPropagationContextEvaluator::setMinSpeculativeOffset(
        long minSpeculativeRefAddress) {
    minSpeculativeOffset = minSpeculativeRefAddress;
    return this;
}

ConstantPropagationContextEvaluator* ConstantPropagationContextEvaluator::setMaxSpeculativeOffset(
        long maxSpeculativeRefAddress) {
    maxSpeculativeOffset = maxSpeculativeRefAddress;
    return this;
}

ConstantPropagationContextEvaluator* ConstantPropagationContextEvaluator::setMinStoreLoadOffset(
        long minStoreLoadRefAddress) {
    maxSpeculativeOffset = minStoreLoadRefAddress;
    return this;
}

ConstantPropagationContextEvaluator* ConstantPropagationContextEvaluator::setCreateComplexDataFromPointers(
        bool doCreateData) {
    createDataFromPointers = doCreateData;
    return this;
}

AddressSet* ConstantPropagationContextEvaluator::getDestinationSet() {
    return &destSet;
}

Address ConstantPropagationContextEvaluator::evaluateConstant(
        VarnodeContext* context, Instruction* instr, int pcodeop,
        const Address& constant, int size, DataType* dataType, const RefType* refType) {
    AddressSpace* space = constant.getAddressSpace();
    if (space == nullptr) return Address();

    int64_t maxAddrOffset = maxOffsetForSpaceSize(space->getSize());
    int64_t wordOffset = constant.getOffset();

    if (((wordOffset >= 0 && wordOffset < minSpeculativeOffset) ||
         (llabs(maxAddrOffset - wordOffset) < maxSpeculativeOffset)) &&
        !space->isExternalSpace()) {
        return Address();
    }

    if (wordOffset == 0xffffffffL || wordOffset == 0xffffL || wordOffset == -1L) {
        return Address();
    }

    return constant;
}

bool ConstantPropagationContextEvaluator::evaluateReference(
        VarnodeContext* context, Instruction* instr, int pcodeop,
        const Address& address, int size, DataType* dataType, const RefType* refType) {
    if (refType->isCall() && !refType->isComputed() && pcodeop == PcodeOp::UNIMPLEMENTED) {
        return true;
    }

    AddressSpace* space = address.getAddressSpace();
    if (space == nullptr) return false;

    if (space->isExternalSpace()) {
        return true;
    }

    int64_t maxAddrOffset = maxOffsetForSpaceSize(space->getSize());
    int64_t wordOffset = address.getAddressableWordOffset();
    bool isKnownReference = !address.isConstantAddress();

    if (pcodeop != PcodeOp::COPY &&
        ((wordOffset >= 0 && wordOffset < minStoreLoadOffset) ||
         (llabs(maxAddrOffset - wordOffset) < minStoreLoadOffset))) {
        if (!isKnownReference) {
            return false;
        }
    }

    Program* program = instr->getProgram();
    if (program == nullptr) return false;

    if (refType->isFlow() && !refType->isIndirect()) {
        Memory* memory = program->getMemory();
        if (memory && !memory->isExternalBlockAddress(address)) {
            // Simplified - just return true for flow references
            // Full implementation would disassemble at flow target
        }
    }

    return true;
}

bool ConstantPropagationContextEvaluator::evaluateDestination(
        VarnodeContext* context, Instruction* instruction) {
    FlowType* flowType = instruction->getFlowType();
    if (!flowType || !flowType->isJump()) {
        return false;
    }

    // Get references from instruction
    auto refs = instruction->getReferencesFrom();
    if (refs.empty() || (refs.size() == 1 && refs[0]->getReferenceType()->isData())) {
        destSet.addRange(instruction->getAddress(), instruction->getAddress());
    }

    return false;
}

bool ConstantPropagationContextEvaluator::allowAccess(
        VarnodeContext* context, const Address& addr) {
    return trustMemoryWrite;
}

} // namespace ghidra
