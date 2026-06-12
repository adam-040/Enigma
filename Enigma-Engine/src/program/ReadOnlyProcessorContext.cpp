/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ReadOnlyProcessorContext.cpp
/// \brief Read-only processor context wrapper (sets are no-ops)
#include <ghidra/ReadOnlyProcessorContext.h>

namespace ghidra {

ReadOnlyProcessorContext::ReadOnlyProcessorContext(ProcessorContextView* context)
    : context_(context) {}

Register* ReadOnlyProcessorContext::getBaseContextRegister() {
    return context_->getBaseContextRegister();
}

std::vector<Register*> ReadOnlyProcessorContext::getRegisters() {
    return context_->getRegisters();
}

Register* ReadOnlyProcessorContext::getRegister(const std::string& name) {
    return context_->getRegister(name);
}

uint64_t ReadOnlyProcessorContext::getValue(Register* reg, bool isSigned) const {
    return context_->getValue(reg, isSigned);
}

RegisterValue* ReadOnlyProcessorContext::getRegisterValue(Register* reg) const {
    return context_->getRegisterValue(reg);
}

bool ReadOnlyProcessorContext::hasValue(Register* reg) const {
    return context_->hasValue(reg);
}

void ReadOnlyProcessorContext::setValue(Register* reg, uint64_t value) {}

void ReadOnlyProcessorContext::setRegisterValue(RegisterValue* value) {}

void ReadOnlyProcessorContext::clearRegister(Register* reg) {}

} // namespace ghidra
