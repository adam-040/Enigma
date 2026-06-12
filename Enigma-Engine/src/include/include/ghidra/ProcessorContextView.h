/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ProcessorContextView.h
/// \brief Read-only view of processor register state
/// Translated from: ghidra.program.model.lang.ProcessorContextView
#pragma once

#include <ghidra/Register.h>
#include <ghidra/RegisterValue.h>
#include <vector>
#include <cstdint>

namespace ghidra {

class ProcessorContextView {
public:
    virtual ~ProcessorContextView() = default;

    virtual Register* getBaseContextRegister() = 0;
    virtual std::vector<Register*> getRegisters() = 0;
    virtual Register* getRegister(const std::string& name) = 0;
    virtual uint64_t getValue(Register* reg, bool isSigned) const = 0;
    virtual RegisterValue* getRegisterValue(Register* reg) const = 0;
    virtual bool hasValue(Register* reg) const = 0;
};

} // namespace ghidra
