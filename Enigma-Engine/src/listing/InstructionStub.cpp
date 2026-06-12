/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/InstructionStub.h>
#include <ghidra/MemBuffer.h>
#include <stdexcept>

namespace ghidra {

Program* InstructionStub::getProgram() const {
    throw std::runtime_error("UnsupportedOperationException");
}

Address InstructionStub::getAddress() const {
    throw std::runtime_error("UnsupportedOperationException");
}

int InstructionStub::getLength() const {
    throw std::runtime_error("UnsupportedOperationException");
}

Memory* InstructionStub::getMemory() const {
    return nullptr;
}

DataType* InstructionStub::getDataType() const {
    throw std::runtime_error("UnsupportedOperationException");
}

std::string InstructionStub::getComment() const {
    throw std::runtime_error("UnsupportedOperationException");
}

void InstructionStub::setComment(const std::string& c) {
    throw std::runtime_error("UnsupportedOperationException");
}

std::string InstructionStub::toString() const {
    throw std::runtime_error("UnsupportedOperationException");
}

} // namespace ghidra
