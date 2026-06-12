/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ReadOnlyProcessorContext.h
/// \brief Read-only processor context wrapper (sets are no-ops)
/// Translated from: ghidra.program.model.lang.ReadOnlyProcessorContext
#pragma once

#include <ghidra/ProcessorContext.h>
#include <ghidra/ProcessorContextView.h>

namespace ghidra {

class ReadOnlyProcessorContext : public ProcessorContext {
public:
    explicit ReadOnlyProcessorContext(ProcessorContextView* context);

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
    ProcessorContextView* context_;
};

} // namespace ghidra
