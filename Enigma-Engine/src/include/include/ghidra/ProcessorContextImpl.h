/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ProcessorContextImpl.h
/// \brief Implementation of processor context with register state
/// Translated from: ghidra.program.model.lang.ProcessorContextImpl
#pragma once

#include <ghidra/ProcessorContext.h>
#include <ghidra/Language.h>
#include <unordered_map>
#include <vector>
#include <cstdint>

namespace ghidra {

class ProcessorContextImpl : public ProcessorContext {
public:
    explicit ProcessorContextImpl(Language* language);

    Register* getBaseContextRegister() override;
    std::vector<Register*> getRegisters() override;
    Register* getRegister(const std::string& name) override;
    uint64_t getValue(Register* reg, bool isSigned) const override;
    RegisterValue* getRegisterValue(Register* reg) const override;
    bool hasValue(Register* reg) const override;

    void setValue(Register* reg, uint64_t value) override;
    void setRegisterValue(RegisterValue* value) override;
    void clearRegister(Register* reg) override;

    void clearAll();

private:
    Language* language_;
    std::unordered_map<Register*, std::vector<uint8_t>> values_;
};

} // namespace ghidra
