/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ProgramProcessorContext.h
/// \brief Bridges ProgramContext to ProcessorContext for a specific address
/// Translated from: ghidra.program.model.lang.ProgramProcessorContext
#pragma once

#include <ghidra/ProcessorContext.h>
#include <ghidra/ProgramContext.h>
#include <ghidra/Address.h>

namespace ghidra {

class ProgramProcessorContext : public ProcessorContext {
public:
    ProgramProcessorContext(ProgramContext* context, const Address& addr);

    Register* getBaseContextRegister() override;
    std::vector<Register*> getRegisters() override;
    Register* getRegister(const std::string& name) override;
    uint64_t getValue(Register* reg, bool isSigned) const override;
    RegisterValue* getRegisterValue(Register* reg) const override;
    bool hasValue(Register* reg) const override;

    void setValue(Register* reg, uint64_t value) override;
    void setRegisterValue(RegisterValue* value) override;
    void clearRegister(Register* reg) override;

private:
    ProgramContext* context_;
    Address addr_;
};

} // namespace ghidra
