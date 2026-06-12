/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/MemoryBlockStub.h>
#include <stdexcept>

namespace ghidra {

MemoryBlockStub::MemoryBlockStub()
    : start_(Address::NO_ADDRESS), end_(Address::NO_ADDRESS) {}

MemoryBlockStub::MemoryBlockStub(const Address& start, const Address& end)
    : start_(start), end_(end) {}

const Address& MemoryBlockStub::getStart() const { return start_; }
const Address& MemoryBlockStub::getEnd() const { return end_; }

AddressRangeImpl MemoryBlockStub::getAddressRange() const {
    return AddressRangeImpl(start_, end_);
}

long long MemoryBlockStub::getSize() const {
    return end_.getOffset() - start_.getOffset() + 1;
}

bool MemoryBlockStub::contains(const Address& addr) const {
    return addr >= start_ && addr <= end_;
}

std::string MemoryBlockStub::getName() const {
    throw std::runtime_error("UnsupportedOperationException");
}

void MemoryBlockStub::setName(const std::string& name) {
    throw std::runtime_error("UnsupportedOperationException");
}

std::string MemoryBlockStub::getComment() const {
    throw std::runtime_error("UnsupportedOperationException");
}

void MemoryBlockStub::setComment(const std::string& comment) {
    throw std::runtime_error("UnsupportedOperationException");
}

std::string MemoryBlockStub::getSourceName() const {
    throw std::runtime_error("UnsupportedOperationException");
}

void MemoryBlockStub::setSourceName(const std::string& sourceName) {
    throw std::runtime_error("UnsupportedOperationException");
}

int MemoryBlockStub::getFlags() const {
    throw std::runtime_error("UnsupportedOperationException");
}

void MemoryBlockStub::setRead(bool r) {
    throw std::runtime_error("UnsupportedOperationException");
}

void MemoryBlockStub::setWrite(bool w) {
    throw std::runtime_error("UnsupportedOperationException");
}

void MemoryBlockStub::setExecute(bool e) {
    throw std::runtime_error("UnsupportedOperationException");
}

void MemoryBlockStub::setVolatile(bool v) {
    throw std::runtime_error("UnsupportedOperationException");
}

void MemoryBlockStub::setArtificial(bool a) {
    throw std::runtime_error("UnsupportedOperationException");
}

MemoryBlockType MemoryBlockStub::getType() const {
    return MemoryBlockType::DEFAULT;
}

bool MemoryBlockStub::isInitialized() const {
    throw std::runtime_error("UnsupportedOperationException");
}

bool MemoryBlockStub::isMapped() const {
    throw std::runtime_error("UnsupportedOperationException");
}

bool MemoryBlockStub::isExternalBlock() const {
    throw std::runtime_error("UnsupportedOperationException");
}

bool MemoryBlockStub::isOverlay() const {
    return false;
}

bool MemoryBlockStub::isLoaded() const {
    throw std::runtime_error("UnsupportedOperationException");
}

uint8_t MemoryBlockStub::getByte(const Address& addr) const {
    throw std::runtime_error("UnsupportedOperationException");
}

int MemoryBlockStub::getBytes(const Address& addr, uint8_t* buf, int len) const {
    throw std::runtime_error("UnsupportedOperationException");
}

void MemoryBlockStub::putByte(const Address& addr, uint8_t value) {
    throw std::runtime_error("UnsupportedOperationException");
}

int MemoryBlockStub::putBytes(const Address& addr, const uint8_t* buf, int len) {
    throw std::runtime_error("UnsupportedOperationException");
}

int MemoryBlockStub::compareTo(const MemoryBlock& other) const {
    throw std::runtime_error("UnsupportedOperationException");
}

} // namespace ghidra
