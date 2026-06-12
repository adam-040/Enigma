/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/StubListing.h>
#include <ghidra/EmptyAddressRangeIterator.h>
#include <ghidra/AddressSetView.h>
#include <stdexcept>

namespace ghidra {

Program* StubListing::getProgram() const {
    throw std::runtime_error("UnsupportedOperationException");
}

Instruction* StubListing::getInstructionAt(Address addr) const {
    throw std::runtime_error("UnsupportedOperationException");
}

Instruction* StubListing::getInstructionContaining(Address addr) const {
    throw std::runtime_error("UnsupportedOperationException");
}

Instruction* StubListing::getInstructionAfter(Address addr) const {
    throw std::runtime_error("UnsupportedOperationException");
}

Data* StubListing::getDataAt(Address addr) const {
    throw std::runtime_error("UnsupportedOperationException");
}

Data* StubListing::getDataContaining(Address addr) const {
    throw std::runtime_error("UnsupportedOperationException");
}

Data* StubListing::getDefinedDataContaining(Address addr) const {
    throw std::runtime_error("UnsupportedOperationException");
}

CodeUnit* StubListing::getCodeUnitAt(Address addr) const {
    throw std::runtime_error("UnsupportedOperationException");
}

CodeUnit* StubListing::getCodeUnitContaining(Address addr) const {
    throw std::runtime_error("UnsupportedOperationException");
}

void StubListing::addInstruction(Instruction* inst) {
    throw std::runtime_error("UnsupportedOperationException");
}

void StubListing::addData(Data* data) {
    throw std::runtime_error("UnsupportedOperationException");
}

Data* StubListing::createData(Address addr, DataType* dataType, int length) {
    throw std::runtime_error("UnsupportedOperationException");
}

void StubListing::removeInstruction(Address addr) {
    throw std::runtime_error("UnsupportedOperationException");
}

void StubListing::removeData(Address addr) {
    throw std::runtime_error("UnsupportedOperationException");
}

bool StubListing::isUndefined(Address addr) const {
    throw std::runtime_error("UnsupportedOperationException");
}

size_t StubListing::getInstructionCount() const {
    throw std::runtime_error("UnsupportedOperationException");
}

size_t StubListing::getDataCount() const {
    throw std::runtime_error("UnsupportedOperationException");
}

std::vector<Instruction*> StubListing::getInstructions(const AddressSetView& set) const {
    throw std::runtime_error("UnsupportedOperationException");
}

std::vector<Data*> StubListing::getData(const AddressSetView& set) const {
    throw std::runtime_error("UnsupportedOperationException");
}

AddressRangeIterator* StubListing::getCommentAddressIterator(const AddressSetView& set, bool forward) const {
    return &EmptyAddressRangeIterator::instance();
}

int StubListing::getCommentAddressCount(const AddressSetView& set) const {
    return 0;
}

std::string StubListing::getComment(Address addr, int commentType) const {
    return "";
}

} // namespace ghidra
