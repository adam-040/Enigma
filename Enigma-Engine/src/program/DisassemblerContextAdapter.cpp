/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DisassemblerContextAdapter.cpp
/// \brief Adapter for DisassemblerContext with UnsupportedOperationException defaults
#include <ghidra/DisassemblerContextAdapter.h>
#include <stdexcept>

namespace ghidra {

Register* DisassemblerContextAdapter::getBaseContextRegister() {
    throw std::runtime_error("UnsupportedOperationException");
}

std::vector<Register*> DisassemblerContextAdapter::getRegisters() {
    throw std::runtime_error("UnsupportedOperationException");
}

Register* DisassemblerContextAdapter::getRegister(const std::string& name) {
    throw std::runtime_error("UnsupportedOperationException");
}

uint64_t DisassemblerContextAdapter::getValue(Register* reg, bool isSigned) const {
    throw std::runtime_error("UnsupportedOperationException");
}

RegisterValue* DisassemblerContextAdapter::getRegisterValue(Register* reg) const {
    throw std::runtime_error("UnsupportedOperationException");
}

bool DisassemblerContextAdapter::hasValue(Register* reg) const {
    throw std::runtime_error("UnsupportedOperationException");
}

void DisassemblerContextAdapter::setValue(Register* reg, uint64_t value) {
    throw std::runtime_error("UnsupportedOperationException");
}

void DisassemblerContextAdapter::setRegisterValue(RegisterValue* value) {
    throw std::runtime_error("UnsupportedOperationException");
}

void DisassemblerContextAdapter::clearRegister(Register* reg) {
    throw std::runtime_error("UnsupportedOperationException");
}

void DisassemblerContextAdapter::setFutureRegisterValue(const Address& address, RegisterValue* value) {
    throw std::runtime_error("UnsupportedOperationException");
}

void DisassemblerContextAdapter::setFutureRegisterValue(const Address& fromAddr, const Address& toAddr, RegisterValue* value) {
    throw std::runtime_error("UnsupportedOperationException");
}

} // namespace ghidra
