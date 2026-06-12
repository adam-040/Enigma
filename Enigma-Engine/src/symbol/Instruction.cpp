/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Instruction.cpp
/// \brief Instruction representation implementation
#include <ghidra/Instruction.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/Scalar.h>
#include <ghidra/Register.h>
#include <ghidra/Program.h>
#include <vector>

namespace ghidra {

Instruction::Instruction(Program* program, Address address, const std::string& mnemonic,
                         int length, FlowType* flowType)
    : CodeUnit(program, address, nullptr), mnemonic_(mnemonic), length_(length), flowType_(flowType) {}

int Instruction::getLength() const {
    return length_;
}

const std::string& Instruction::getOperandRefString(int index) const {
    static const std::string empty;
    if (index < 0 || index >= static_cast<int>(operands_.size())) return empty;
    return operands_[index];
}

void Instruction::setOperand(int index, const std::string& ref) {
    if (index >= static_cast<int>(operands_.size())) {
        operands_.resize(index + 1);
    }
    operands_[index] = ref;
}

bool Instruction::hasPcode() const {
    return !pcode_.empty();
}

std::string Instruction::toString() const {
    std::string result = mnemonic_;
    if (!operands_.empty()) {
        result += " ";
        for (size_t i = 0; i < operands_.size(); ++i) {
            if (i > 0) result += ", ";
            result += operands_[i];
        }
    }
    return result;
}

std::string Instruction::getDefaultLabelRepresentation() const {
    return mnemonic_;
}

Address Instruction::getFallThrough() const {
    return fallThrough_.isValid() ? fallThrough_ : getDefaultFallThrough();
}

Address Instruction::getDefaultFallThrough() const {
    return address_.isValid() ? address_.add(getLength()) : Address::NO_ADDRESS;
}

Instruction::OperandInfo& Instruction::getOrCreateOperandInfo(int opIndex) {
    if (opIndex >= static_cast<int>(operandInfos_.size())) {
        operandInfos_.resize(opIndex + 1);
    }
    return operandInfos_[opIndex];
}

std::vector<Scalar*> Instruction::getOperandScalars(int opIndex) const {
    if (opIndex < 0 || opIndex >= static_cast<int>(operandInfos_.size()))
        return {};
    return operandInfos_[opIndex].scalars;
}

void Instruction::addOperandScalar(int opIndex, Scalar* s) {
    getOrCreateOperandInfo(opIndex).scalars.push_back(s);
    scalars_.push_back(s);
}

std::vector<Register*> Instruction::getOperandRegisters(int opIndex) const {
    if (opIndex < 0 || opIndex >= static_cast<int>(operandInfos_.size()))
        return {};
    return operandInfos_[opIndex].registers;
}

void Instruction::addOperandRegister(int opIndex, Register* r) {
    getOrCreateOperandInfo(opIndex).registers.push_back(r);
}

Reference* Instruction::addOperandReference(int opIndex, Address toAddr,
                                              const RefType* type, SourceType source) {
    if (!program_) return nullptr;
    return program_->getReferenceManager()->addMemoryReference(
        address_, toAddr, type, source, opIndex);
}

std::vector<Reference*> Instruction::getOperandReferences(int opIndex) const {
    if (!program_) return {};
    return program_->getReferenceManager()->getReferencesFrom(address_, opIndex);
}

} // namespace ghidra
