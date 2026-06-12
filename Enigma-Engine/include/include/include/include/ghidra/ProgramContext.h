/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ProgramContext.h
/// \brief Program context interface
/// Translated from: ghidra.program.model.listing.ProgramContext
#pragma once

#include <ghidra/Address.h>
#include <ghidra/Register.h>
#include <ghidra/RegisterValue.h>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace ghidra {

class ProgramContext {
public:
    virtual ~ProgramContext() = default;

    virtual void setValue(Register* reg, uint64_t value, const Address& start, const Address& end) = 0;
    virtual void setRegisterValue(RegisterValue* value, const Address& start, const Address& end) = 0;
    virtual void clearRegister(Register* reg, const Address& start, const Address& end) = 0;
    virtual uint64_t getValue(Register* reg, const Address& address) const = 0;
    virtual RegisterValue* getRegisterValue(Register* reg, const Address& address) const = 0;
    virtual Register* getContextRegister() const = 0;
    virtual void setContextRegister(Register* reg) = 0;
};

} // namespace ghidra
