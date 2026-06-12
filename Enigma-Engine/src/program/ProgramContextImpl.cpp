/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ProgramContextImpl.cpp
/// \brief Implementation of program context for register values
/// Translated from: ghidra.program.database.register.ProgramRegisterContextDB

#include <ghidra/ProgramContextImpl.h>

namespace ghidra {

void ProgramContextImpl::setValue(Register* reg, uint64_t value, const Address& start, const Address& end) {
    RangeKey key(reg, start, end);
    uint64Values_[key] = value;
}

void ProgramContextImpl::setRegisterValue(RegisterValue* value, const Address& start, const Address& end) {
    if (value) {
        RangeKey key(value->getRegister(), start, end);
        auto ownedVal = std::make_unique<RegisterValue>(*value);
        RegisterValue* raw = ownedVal.get();
        ownedRegisterValues_.push_back(std::move(ownedVal));
        regValues_[key] = raw;
    }
}

void ProgramContextImpl::clearRegister(Register* reg, const Address& start, const Address& end) {
    RangeKey key(reg, start, end);
    uint64Values_.erase(key);
    regValues_.erase(key);
}

uint64_t ProgramContextImpl::getValue(Register* reg, const Address& address) const {
    for (const auto& pair : uint64Values_) {
        if (pair.first.reg == reg && pair.first.start <= address && pair.first.end >= address) {
            return pair.second;
        }
    }
    return 0;
}

RegisterValue* ProgramContextImpl::getRegisterValue(Register* reg, const Address& address) const {
    for (const auto& pair : regValues_) {
        if (pair.first.reg == reg && pair.first.start <= address && pair.first.end >= address) {
            return pair.second;
        }
    }
    return nullptr;
}

void ProgramContextImpl::setDefaultValue(RegisterValue* value, const Address& start, const Address& end) {
    if (value) {
        RangeKey key(value->getRegister(), start, end);
        auto ownedVal = std::make_unique<RegisterValue>(*value);
        RegisterValue* raw = ownedVal.get();
        ownedRegisterValues_.push_back(std::move(ownedVal));
        defaultValues_[key] = raw;
    }
}

RegisterValue* ProgramContextImpl::getDefaultValue(Register* reg, const Address& address) const {
    for (const auto& pair : defaultValues_) {
        if (pair.first.reg == reg && pair.first.start <= address && pair.first.end >= address) {
            return pair.second;
        }
    }
    return nullptr;
}

void ProgramContextImpl::clearAll() {
    uint64Values_.clear();
    regValues_.clear();
    defaultValues_.clear();
    ownedRegisterValues_.clear();
}

} // namespace ghidra
