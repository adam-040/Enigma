/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file RefTypeFactory.cpp
/// \brief Factory class to create RefType objects
#include <ghidra/RefTypeFactory.h>
#include <ghidra/Instruction.h>
#include <ghidra/CodeUnit.h>
#include <ghidra/Program.h>
#include <ghidra/Register.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/PcodeOp.h>
#include <ghidra/Varnode.h>
#include <ghidra/Scalar.h>
#include <stdexcept>

namespace ghidra {

static const RefType* lookupTable[128] = {nullptr};
static bool lookupInitialized = false;

static void initLookup() {
    if (lookupInitialized) return;
    lookupInitialized = true;

    auto put = [](int8_t v, const RefType* rt) {
        if (v >= 0 && v < 128) lookupTable[v] = rt;
    };

    put(RefTypes::INVALID.getValue(), &RefTypes::INVALID);
    put(RefTypes::FLOW.getValue(), &RefTypes::FLOW);
    put(RefTypes::FALL_THROUGH.getValue(), &RefTypes::FALL_THROUGH);
    put(RefTypes::UNCONDITIONAL_JUMP.getValue(), &RefTypes::UNCONDITIONAL_JUMP);
    put(RefTypes::CONDITIONAL_JUMP.getValue(), &RefTypes::CONDITIONAL_JUMP);
    put(RefTypes::UNCONDITIONAL_CALL.getValue(), &RefTypes::UNCONDITIONAL_CALL);
    put(RefTypes::CONDITIONAL_CALL.getValue(), &RefTypes::CONDITIONAL_CALL);
    put(RefTypes::TERMINATOR.getValue(), &RefTypes::TERMINATOR);
    put(RefTypes::COMPUTED_JUMP.getValue(), &RefTypes::COMPUTED_JUMP);
    put(RefTypes::CONDITIONAL_TERMINATOR.getValue(), &RefTypes::CONDITIONAL_TERMINATOR);
    put(RefTypes::COMPUTED_CALL.getValue(), &RefTypes::COMPUTED_CALL);
    put(RefTypes::CONDITIONAL_COMPUTED_CALL.getValue(), &RefTypes::CONDITIONAL_COMPUTED_CALL);
    put(RefTypes::CONDITIONAL_COMPUTED_JUMP.getValue(), &RefTypes::CONDITIONAL_COMPUTED_JUMP);
    put(RefTypes::CALL_TERMINATOR.getValue(), &RefTypes::CALL_TERMINATOR);
    put(RefTypes::COMPUTED_CALL_TERMINATOR.getValue(), &RefTypes::COMPUTED_CALL_TERMINATOR);
    put(RefTypes::CONDITIONAL_CALL_TERMINATOR.getValue(), &RefTypes::CONDITIONAL_CALL_TERMINATOR);
    put(RefTypes::JUMP_TERMINATOR.getValue(), &RefTypes::JUMP_TERMINATOR);
    put(RefTypes::INDIRECTION.getValue(), &RefTypes::INDIRECTION);
    put(RefTypes::DATA.getValue(), &RefTypes::DATA);
    put(RefTypes::PARAM.getValue(), &RefTypes::PARAM);
    put(RefTypes::DATA_IND.getValue(), &RefTypes::DATA_IND);
    put(RefTypes::READ.getValue(), &RefTypes::READ);
    put(RefTypes::WRITE.getValue(), &RefTypes::WRITE);
    put(RefTypes::READ_WRITE.getValue(), &RefTypes::READ_WRITE);
    put(RefTypes::READ_IND.getValue(), &RefTypes::READ_IND);
    put(RefTypes::WRITE_IND.getValue(), &RefTypes::WRITE_IND);
    put(RefTypes::READ_WRITE_IND.getValue(), &RefTypes::READ_WRITE_IND);
    put(RefTypes::EXTERNAL_REF.getValue(), &RefTypes::EXTERNAL_REF);
    put(RefTypes::CALL_OVERRIDE_UNCONDITIONAL.getValue(), &RefTypes::CALL_OVERRIDE_UNCONDITIONAL);
    put(RefTypes::JUMP_OVERRIDE_UNCONDITIONAL.getValue(), &RefTypes::JUMP_OVERRIDE_UNCONDITIONAL);
    put(RefTypes::CALLOTHER_OVERRIDE_CALL.getValue(), &RefTypes::CALLOTHER_OVERRIDE_CALL);
    put(RefTypes::CALLOTHER_OVERRIDE_JUMP.getValue(), &RefTypes::CALLOTHER_OVERRIDE_JUMP);
}

const RefType* RefTypeFactory::get(int8_t type) {
    initLookup();
    if (type >= 0 && type < 128 && lookupTable[type] != nullptr) {
        return lookupTable[type];
    }
    throw std::out_of_range("RefType not defined: " + std::to_string(type));
}

std::vector<const RefType*> RefTypeFactory::getMemoryRefTypes() {
    return {
        &RefTypes::INDIRECTION, &RefTypes::COMPUTED_CALL, &RefTypes::COMPUTED_JUMP,
        &RefTypes::CONDITIONAL_CALL, &RefTypes::CONDITIONAL_JUMP,
        &RefTypes::UNCONDITIONAL_CALL, &RefTypes::UNCONDITIONAL_JUMP,
        &RefTypes::CONDITIONAL_COMPUTED_CALL, &RefTypes::CONDITIONAL_COMPUTED_JUMP,
        &RefTypes::PARAM, &RefTypes::DATA, &RefTypes::DATA_IND,
        &RefTypes::READ, &RefTypes::READ_IND, &RefTypes::WRITE, &RefTypes::WRITE_IND,
        &RefTypes::READ_WRITE, &RefTypes::READ_WRITE_IND,
        &RefTypes::CALL_OVERRIDE_UNCONDITIONAL, &RefTypes::JUMP_OVERRIDE_UNCONDITIONAL,
        &RefTypes::CALLOTHER_OVERRIDE_CALL, &RefTypes::CALLOTHER_OVERRIDE_JUMP
    };
}

std::vector<const RefType*> RefTypeFactory::getStackRefTypes() {
    return { &RefTypes::DATA, &RefTypes::READ, &RefTypes::WRITE, &RefTypes::READ_WRITE };
}

std::vector<const RefType*> RefTypeFactory::getDataRefTypes() {
    return { &RefTypes::DATA, &RefTypes::PARAM, &RefTypes::READ, &RefTypes::WRITE, &RefTypes::READ_WRITE };
}

std::vector<const RefType*> RefTypeFactory::getExternalRefTypes() {
    return {
        &RefTypes::COMPUTED_CALL, &RefTypes::COMPUTED_JUMP,
        &RefTypes::CONDITIONAL_CALL, &RefTypes::CONDITIONAL_JUMP,
        &RefTypes::UNCONDITIONAL_CALL, &RefTypes::UNCONDITIONAL_JUMP,
        &RefTypes::CONDITIONAL_COMPUTED_CALL, &RefTypes::CONDITIONAL_COMPUTED_JUMP,
        &RefTypes::DATA, &RefTypes::DATA_IND,
        &RefTypes::READ, &RefTypes::READ_IND, &RefTypes::WRITE, &RefTypes::WRITE_IND,
        &RefTypes::READ_WRITE, &RefTypes::READ_WRITE_IND,
        &RefTypes::CALL_OVERRIDE_UNCONDITIONAL, &RefTypes::CALLOTHER_OVERRIDE_CALL,
        &RefTypes::CALLOTHER_OVERRIDE_JUMP
    };
}

const RefType* RefTypeFactory::getDefaultRegisterRefType(CodeUnit* cu, Register* reg, int opIndex) {
    const RefType* rt = &RefTypes::DATA;
    if (auto* instr = dynamic_cast<Instruction*>(cu)) {
        for (auto* r : instr->getResultObjects()) {
            if (reg == r) {
                rt = &RefTypes::WRITE;
                break;
            }
        }
        for (auto* r : instr->getInputObjects()) {
            if (reg == r) {
                rt = (rt == &RefTypes::WRITE) ? &RefTypes::READ_WRITE : &RefTypes::READ;
                break;
            }
        }
    }
    return rt;
}

const RefType* RefTypeFactory::getDefaultStackRefType(CodeUnit* cu, int opIndex) {
    auto* instr = dynamic_cast<Instruction*>(cu);
    if (!instr) return &RefTypes::DATA;
    return &RefTypes::DATA;
}

const FlowType* RefTypeFactory::getDefaultFlowType(Instruction* instr, const Address& toAddr,
                                                     bool allowComputedFlowType) {
    if (!toAddr.isMemoryAddress() && !toAddr.isExternalAddress()) {
        throw std::invalid_argument("Unsupported toAddr address space type");
    }
    const FlowType* flowType = getDefaultJumpOrCallFlowType(instr);
    if (flowType != nullptr && (!flowType->isComputed() || allowComputedFlowType)) {
        return flowType;
    }
    if (allowComputedFlowType && flowType == nullptr) {
        flowType = getDefaultComputedFlowType(instr);
    }
    return flowType;
}

const FlowType* RefTypeFactory::getDefaultComputedFlowType(Instruction* instr) {
    auto* ft = instr->getFlowType();
    if (ft == nullptr) return nullptr;

    bool hasBranchInd = false;
    bool hasCallInd = false;

    for (auto* op : instr->getPcode()) {
        int opcode = op->getOpcode();
        if (opcode == PcodeOp::BRANCHIND) hasBranchInd = true;
        else if (opcode == PcodeOp::CALLIND) hasCallInd = true;
    }

    if (hasBranchInd && hasCallInd) return nullptr;
    if (hasBranchInd) return &RefTypes::CONDITIONAL_COMPUTED_JUMP;
    if (hasCallInd) return &RefTypes::CONDITIONAL_COMPUTED_CALL;
    return nullptr;
}

const RefType* RefTypeFactory::getDefaultMemoryRefType(CodeUnit* cu, int opIndex,
                                                        const Address& toAddr,
                                                        bool ignoreExistingReferences) {
    const RefType* refType = nullptr;
    if (toAddr.isValid() && cu && cu->getProgram()) {
        auto* block = cu->getProgram()->getMemory()->getBlock(toAddr);
        if (block != nullptr && block->isMapped()) {
            ignoreExistingReferences = true;
        }
    }

    if (toAddr.isValid() && dynamic_cast<Instruction*>(cu) != nullptr) {
        auto* instr = dynamic_cast<Instruction*>(cu);

        for (auto* resultObj : instr->getResultObjects()) {
            if (resultObj->getAddress() == toAddr) {
                refType = &RefTypes::WRITE;
                break;
            }
        }
        for (auto* inputObj : instr->getInputObjects()) {
            if (inputObj->getAddress() == toAddr) {
                if (refType == &RefTypes::WRITE) return &RefTypes::READ_WRITE;
                refType = &RefTypes::READ;
            }
        }
        if (refType != nullptr) return refType;
    }

    if (!ignoreExistingReferences && cu && cu->getProgram()) {
        auto* refMgr = cu->getProgram()->getReferenceManager();
        if (refMgr) {
            auto refs = refMgr->getReferencesFrom(cu->getAddress(), opIndex);
            for (auto* ref : refs) {
                if (ref->getToAddress() == toAddr) return ref->getReferenceType();
                if (ref->isPrimary()) refType = ref->getReferenceType();
            }
            if (refType != nullptr) return refType;
        }
    }

    if (auto* inst = dynamic_cast<Instruction*>(cu)) {
        refType = getDefaultComputedFlowType(inst);
        if (refType != nullptr) return refType;
    }

    return &RefTypes::DATA;
}

const FlowType* RefTypeFactory::getDefaultJumpOrCallFlowType(Instruction* instr) {
    auto* flowType = instr->getFlowType();
    if (flowType == nullptr) return nullptr;

    if (flowType->isConditional()) {
        if (flowType->isComputed()) {
            if (flowType->isCall()) return &RefTypes::CONDITIONAL_COMPUTED_CALL;
            if (flowType->isJump()) return &RefTypes::CONDITIONAL_COMPUTED_JUMP;
        }
        if (flowType->isCall()) return &RefTypes::CONDITIONAL_CALL;
        if (flowType->isJump()) return &RefTypes::CONDITIONAL_JUMP;
    }
    if (flowType->isComputed()) {
        if (flowType->isCall()) return &RefTypes::COMPUTED_CALL;
        if (flowType->isJump()) return &RefTypes::COMPUTED_JUMP;
    }
    if (flowType->isCall()) return &RefTypes::UNCONDITIONAL_CALL;
    if (flowType->isJump()) return &RefTypes::UNCONDITIONAL_JUMP;
    return nullptr;
}

const RefType* RefTypeFactory::getMemRefType(Instruction* instr, const Address& memAddr) {
    long memOffset = memAddr.getAddressableWordOffset();
    const RefType* refType = nullptr;

    for (auto* op : instr->getPcode()) {
        const auto& inputs = op->getInputs();
        if (op->getOpcode() == PcodeOp::INT_ZEXT || op->getOpcode() == PcodeOp::COPY) {
            if (!inputs.empty() && inputs[0]->isConstant() && inputs[0]->getOffset() == memOffset) {
                refType = &RefTypes::DATA;
                continue;
            }
        }
        if (op->getOpcode() == PcodeOp::STORE) {
            if (inputs.size() >= 2 &&
                memOffset == inputs[1]->getOffset()) {
                if (refType != nullptr && refType->isRead()) return &RefTypes::READ_WRITE;
                refType = &RefTypes::WRITE;
            }
        } else if (op->getOpcode() == PcodeOp::LOAD) {
            if (inputs.size() >= 2 &&
                memOffset == inputs[1]->getOffset()) {
                if (refType != nullptr && refType->isWrite()) return &RefTypes::READ_WRITE;
                refType = &RefTypes::READ;
            }
        } else {
            for (auto* in : inputs) {
                if (refType == nullptr && in->isConstant() && in->getOffset() == memOffset) {
                    refType = &RefTypes::DATA;
                } else if (in->isAddress() && in->getAddress().getOffset() == memAddr.getOffset()) {
                    if (refType != nullptr && refType->isWrite()) return &RefTypes::READ_WRITE;
                    refType = &RefTypes::READ;
                }
            }
        }
    }
    return refType;
}

const RefType* RefTypeFactory::getLoadStoreRefType(const std::vector<PcodeOp*>& ops, int startOpSeq,
                                                     const Address& offsetAddr,
                                                     const RefType* refType) {
    for (int opSeq = startOpSeq; opSeq < static_cast<int>(ops.size()); opSeq++) {
        auto* op = ops[opSeq];
        int opCode = op->getOpcode();
        const auto& inputs = op->getInputs();

        if (opCode == PcodeOp::LOAD) {
            if (inputs.size() >= 2 && inputs[1]->getAddress() == offsetAddr) {
                if (refType == &RefTypes::WRITE) return &RefTypes::READ_WRITE;
                refType = &RefTypes::READ;
            }
        } else if (opCode == PcodeOp::STORE) {
            if (inputs.size() >= 2 && inputs[1]->getAddress() == offsetAddr) {
                if (refType == &RefTypes::READ) return &RefTypes::READ_WRITE;
                refType = &RefTypes::WRITE;
            }
        }
    }
    return refType;
}

bool RefTypeFactory::isFlowOp(const PcodeOp* op) {
    int opcode = op->getOpcode();
    return opcode == PcodeOp::CALL || opcode == PcodeOp::CALLIND ||
           opcode == PcodeOp::CBRANCH || opcode == PcodeOp::BRANCH ||
           opcode == PcodeOp::BRANCHIND;
}

} // namespace ghidra
