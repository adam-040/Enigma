/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/DataStub.h>
#include <ghidra/MemBuffer.h>
#include <stdexcept>

namespace ghidra {

Program* DataStub::getProgram() const {
    throw std::runtime_error("UnsupportedOperationException");
}

Address DataStub::getAddress() const {
    throw std::runtime_error("UnsupportedOperationException");
}

int DataStub::getLength() const {
    throw std::runtime_error("UnsupportedOperationException");
}

Memory* DataStub::getMemory() const {
    return nullptr;
}

DataType* DataStub::getDataType() const {
    throw std::runtime_error("UnsupportedOperationException");
}

std::string DataStub::getComment() const {
    throw std::runtime_error("UnsupportedOperationException");
}

void DataStub::setComment(const std::string& c) {
    throw std::runtime_error("UnsupportedOperationException");
}

std::string DataStub::toString() const {
    throw std::runtime_error("UnsupportedOperationException");
}

} // namespace ghidra
