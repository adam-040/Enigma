/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/StubMemory.h>
#include <ghidra/AddressSpace.h>
#include <stdexcept>
#include <algorithm>
#include <cstring>

namespace ghidra {

StubMemory::StubMemory() : block_(Address(), Address()) {
    bytes_.resize(8, 0);
    GenericAddressSpace space("Mem", 32, AddressSpace::TYPE_RAM, 0);
    Address start(&space, 0);
    Address end(&space, static_cast<int64_t>(bytes_.size()) - 1);
    block_ = MemoryBlockStub(start, end);
    add(start, end);
}

StubMemory::StubMemory(const std::vector<uint8_t>& bytes) : bytes_(bytes), block_() {
    GenericAddressSpace space("Mem", 32, AddressSpace::TYPE_RAM, 0);
    if (!bytes_.empty()) {
        Address start(&space, 0);
        Address end(&space, static_cast<int64_t>(bytes_.size()) - 1);
        block_ = MemoryBlockStub(start, end);
        add(start, end);
    }
}

bool StubMemory::isBigEndian() const {
    throw std::runtime_error("UnsupportedOperationException");
}

long long StubMemory::getSize() const {
    return static_cast<long long>(bytes_.size());
}

MemoryBlock* StubMemory::getBlock(const Address& addr) {
    return &block_;
}

MemoryBlock* StubMemory::getBlock(const std::string& blockName) {
    return &block_;
}

std::vector<MemoryBlock*> StubMemory::getBlocks() {
    return { &block_ };
}

uint8_t StubMemory::getByte(const Address& addr) {
    int64_t off = addr.getOffset();
    if (off >= 0 && off < static_cast<int64_t>(bytes_.size())) {
        return bytes_[static_cast<size_t>(off)];
    }
    throw std::runtime_error("MemoryAccessException");
}

int StubMemory::getBytes(const Address& addr, uint8_t* dest, int size) {
    int64_t off = addr.getOffset();
    int n = std::min(size, std::max(0, static_cast<int>(static_cast<int64_t>(bytes_.size()) - off)));
    if (n > 0) {
        std::memcpy(dest, bytes_.data() + off, static_cast<size_t>(n));
    }
    return n;
}

void StubMemory::setByte(const Address& addr, uint8_t value) {
    int64_t off = addr.getOffset();
    if (off >= 0 && off < static_cast<int64_t>(bytes_.size())) {
        bytes_[static_cast<size_t>(off)] = value;
        return;
    }
    throw std::runtime_error("UnsupportedOperationException");
}

void StubMemory::setBytes(const Address& addr, const uint8_t* source, int size) {
    int64_t off = addr.getOffset();
    if (off >= 0 && off + size <= static_cast<int64_t>(bytes_.size())) {
        std::memcpy(bytes_.data() + off, source, static_cast<size_t>(size));
        return;
    }
    throw std::runtime_error("UnsupportedOperationException");
}

uint16_t StubMemory::getShort(const Address& addr) {
    throw std::runtime_error("UnsupportedOperationException");
}

uint16_t StubMemory::getShort(const Address& addr, bool bigEndian) {
    throw std::runtime_error("UnsupportedOperationException");
}

uint32_t StubMemory::getInt(const Address& addr) {
    throw std::runtime_error("UnsupportedOperationException");
}

uint32_t StubMemory::getInt(const Address& addr, bool bigEndian) {
    throw std::runtime_error("UnsupportedOperationException");
}

uint64_t StubMemory::getLong(const Address& addr) {
    throw std::runtime_error("UnsupportedOperationException");
}

uint64_t StubMemory::getLong(const Address& addr, bool bigEndian) {
    throw std::runtime_error("UnsupportedOperationException");
}

void StubMemory::setShort(const Address& addr, uint16_t value) {
    throw std::runtime_error("UnsupportedOperationException");
}

void StubMemory::setShort(const Address& addr, uint16_t value, bool bigEndian) {
    throw std::runtime_error("UnsupportedOperationException");
}

void StubMemory::setInt(const Address& addr, uint32_t value) {
    throw std::runtime_error("UnsupportedOperationException");
}

void StubMemory::setInt(const Address& addr, uint32_t value, bool bigEndian) {
    throw std::runtime_error("UnsupportedOperationException");
}

void StubMemory::setLong(const Address& addr, uint64_t value) {
    throw std::runtime_error("UnsupportedOperationException");
}

void StubMemory::setLong(const Address& addr, uint64_t value, bool bigEndian) {
    throw std::runtime_error("UnsupportedOperationException");
}

} // namespace ghidra
