/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ProgramProcessorContext.cpp
/// \brief Bridges ProgramContext to ProcessorContext for a specific address
#include <ghidra/ProgramProcessorContext.h>

namespace ghidra {

ProgramProcessorContext::ProgramProcessorContext(ProgramContext* context, const Address& addr)
    : context_(context), addr_(addr) {}

Register* ProgramProcessorContext::getBaseContextRegister() {
    return context_->getContextRegister();
}

std::vector<Register*> ProgramProcessorContext::getRegisters() {
    return {};
}

Register* ProgramProcessorContext::getRegister(const std::string& name) {
    return nullptr;
}

uint64_t ProgramProcessorContext::getValue(Register* reg, bool isSigned) const {
    return context_->getValue(reg, addr_);
}

RegisterValue* ProgramProcessorContext::getRegisterValue(Register* reg) const {
    return context_->getRegisterValue(reg, addr_);
}

bool ProgramProcessorContext::hasValue(Register* reg) const {
    return context_->getValue(reg, addr_) != 0;
}

void ProgramProcessorContext::setValue(Register* reg, uint64_t value) {
    context_->setValue(reg, value, addr_, addr_);
}

void ProgramProcessorContext::setRegisterValue(RegisterValue* value) {
    context_->setRegisterValue(value, addr_, addr_);
}

void ProgramProcessorContext::clearRegister(Register* reg) {
    context_->clearRegister(reg, addr_, addr_);
}

} // namespace ghidra
