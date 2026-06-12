/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Instruction.h
/// \brief Instruction representation in the program listing
/// Translated from: ghidra.program.model.listing.Instruction
#pragma once

#include <ghidra/CodeUnit.h>
#include <ghidra/RefType.h>
#include <ghidra/FlowOverride.h>
#include <ghidra/SourceType.h>
#include <string>
#include <vector>
#include <cstdint>
#include <memory>

namespace ghidra {

class Register;
class Context;
class Scalar;
class Varnode;
class PcodeOp;

class Instruction : public CodeUnit {
public:
    Instruction() = default;
    Instruction(Program* program, Address address, const std::string& mnemonic,
                int length, FlowType* flowType = nullptr);

    int getLength() const override;

    const std::string& getMnemonicString() const { return mnemonic_; }
    void setMnemonic(const std::string& m) { mnemonic_ = m; }

    FlowType* getFlowType() const { return flowType_; }
    void setFlowType(FlowType* type) { flowType_ = type; }

    int getNumOperands() const { return static_cast<int>(operands_.size()); }

    const std::string& getOperandRefString(int index) const;
    void setOperand(int index, const std::string& ref);

    const std::vector<Register*>& getInputObjects() const { return inputs_; }
    void addInputObject(Register* reg) { inputs_.push_back(reg); }

    const std::vector<Register*>& getResultObjects() const { return results_; }
    void addResultObject(Register* reg) { results_.push_back(reg); }

    const std::vector<Scalar*>& getScalars() const { return scalars_; }
    void addScalar(Scalar* s) { scalars_.push_back(s); }

    const std::vector<Varnode*>& getFlows() const { return flows_; }
    void addFlow(Varnode* vn) { flows_.push_back(vn); }

    const std::vector<PcodeOp*>& getPcode() const { return pcode_; }
    void addPcode(PcodeOp* op) { pcode_.push_back(op); }

    bool hasPcode() const;

    FlowOverride getFlowOverride() const { return flowOverride_; }
    void setFlowOverride(FlowOverride fo) { flowOverride_ = fo; }

    Address getFallFrom() const;
    Instruction* getNext() const;
    bool isInDelaySlot() const { return false; }

    Address getMinAddress() const { return getAddress(); }
    int getDefaultFallThroughOffset() const { return getLength(); }

    Address getFallThrough() const;
    void setFallThrough(const Address& addr) { fallThrough_ = addr; }
    Address getDefaultFallThrough() const;

    bool isLengthOverridden() const { return lengthOverridden_; }
    void setLengthOverridden(bool val) { lengthOverridden_ = val; }

    // Per-operand object access (for analyzer use)
    std::vector<Scalar*> getOperandScalars(int opIndex) const;
    void addOperandScalar(int opIndex, Scalar* s);
    std::vector<Register*> getOperandRegisters(int opIndex) const;
    void addOperandRegister(int opIndex, Register* r);

    // Reference convenience methods
    Reference* addOperandReference(int opIndex, Address toAddr, const RefType* type,
                                    SourceType source);
    std::vector<Reference*> getOperandReferences(int opIndex) const;

    std::string toString() const override;
    std::string getDefaultLabelRepresentation() const;

private:
    struct OperandInfo {
        std::vector<Scalar*> scalars;
        std::vector<Register*> registers;
    };
    OperandInfo& getOrCreateOperandInfo(int opIndex);

    std::string mnemonic_;
    int length_ = 0;
    FlowType* flowType_ = nullptr;
    std::vector<std::string> operands_;
    std::vector<Register*> inputs_;
    std::vector<Register*> results_;
    std::vector<Scalar*> scalars_;
    std::vector<Varnode*> flows_;
    std::vector<PcodeOp*> pcode_;
    std::vector<OperandInfo> operandInfos_;

    FlowOverride flowOverride_ = FlowOverride::NONE;
    Address fallThrough_;
    bool lengthOverridden_ = false;
};

} // namespace ghidra
