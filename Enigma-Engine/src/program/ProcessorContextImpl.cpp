/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ProcessorContextImpl.cpp
/// \brief Implementation of processor context with register state
#include <ghidra/ProcessorContextImpl.h>
#include <algorithm>
#include <cstring>

namespace ghidra {

ProcessorContextImpl::ProcessorContextImpl(Language* language)
    : language_(language) {}

Register* ProcessorContextImpl::getBaseContextRegister() {
    return language_->getContextBaseRegister();
}

std::vector<Register*> ProcessorContextImpl::getRegisters() {
    return language_->getRegisters();
}

Register* ProcessorContextImpl::getRegister(const std::string& name) {
    return language_->getRegister(name);
}

uint64_t ProcessorContextImpl::getValue(Register* reg, bool isSigned) const {
    auto it = values_.find(reg);
    if (it == values_.end()) return 0;
    uint64_t result = 0;
    size_t n = std::min(it->second.size(), sizeof(uint64_t));
    std::memcpy(&result, it->second.data(), n);
    return result;
}

RegisterValue* ProcessorContextImpl::getRegisterValue(Register* reg) const {
    auto it = values_.find(reg);
    if (it == values_.end()) return nullptr;
    return new RegisterValue(reg, it->second);
}

bool ProcessorContextImpl::hasValue(Register* reg) const {
    return values_.find(reg) != values_.end();
}

void ProcessorContextImpl::setValue(Register* reg, uint64_t value) {
    std::vector<uint8_t> bytes(sizeof(uint64_t));
    std::memcpy(bytes.data(), &value, sizeof(uint64_t));
    values_[reg] = std::move(bytes);
}

void ProcessorContextImpl::setRegisterValue(RegisterValue* value) {
    if (!value || !value->getRegister()) return;
    values_[value->getRegister()] = value->getValue();
}

void ProcessorContextImpl::clearRegister(Register* reg) {
    values_.erase(reg);
}

void ProcessorContextImpl::clearAll() {
    values_.clear();
}

} // namespace ghidra
