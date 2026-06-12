/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file InvalidPrototype.h
/// \brief InstructionPrototype returned when an instruction cannot be parsed.
///        Reports a 1-byte length and emits a single UNIMPLEMENTED pcode op.
/// Translated from: ghidra.program.model.lang.InvalidPrototype
#pragma once

#include "ghidra/InstructionPrototype.h"
#include "ghidra/ParserContext.h"
#include <string>
#include <vector>

namespace ghidra {

class Language;
class FlowType;
class RegisterValue;
class VariableOffset;
class Scalar;
class PcodeOp;

class InvalidPrototype : public InstructionPrototype, public ParserContext {
public:
    explicit InvalidPrototype(Language* lang);

    bool hasDelaySlots() const { return false; }
    bool hasCrossBuildDependency() const { return false; }
    bool hasNext2Dependency() const { return false; }
    bool isInDelaySlot() const { return false; }
    int getNumOperands() const { return 1; }
    int getDelaySlotByteCount() const { return 0; }

    ParserContext* getParserContext(MemBuffer* buf, ProcessorContext* processorContext) override;
    int getInstructionLength() const override { return 1; }
    int getDelaySlotDepth() const override { return 0; }
    FlowType* getFlowType() override;
    std::vector<RegisterValue*> getContextChanges() override { return {}; }
    std::vector<VariableOffset*> getFlows() override { return {}; }
    std::vector<Scalar*> getScalars() override { return {}; }
    std::vector<PcodeOp*> getPcodeOps() override;
    bool isEquivalent(const InstructionPrototype* other) const override;

    Address getAddress() const override { return Address::NO_ADDRESS; }
    int getLength() const override { return 1; }
    std::vector<PcodeOp*> getPcodeOps() const override { return {}; }
    std::vector<Varnode*> getInputs() const override { return {}; }
    std::vector<Varnode*> getOutputs() const override { return {}; }
    FlowType* getFlowType() const override;
    RegisterValue* getRegisterValue(Register* reg) const override { (void)reg; return nullptr; }
    void setRegisterValue(Register* reg, RegisterValue* value) override { (void)reg; (void)value; }
    std::string getMnemonic() const override { return "BAD-Instruction"; }
    std::vector<std::string> getOpRepresentations() const override { return {}; }

    Language* getLanguage() const { return language; }

private:
    Language* language;
};

} // namespace ghidra
