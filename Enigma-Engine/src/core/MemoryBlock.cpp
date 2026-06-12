/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file MemoryBlock.cpp
/// \brief Memory block interface implementations
#include <ghidra/MemoryBlock.h>

namespace ghidra {

AddressRangeImpl MemoryBlock::getAddressRange() const {
    return AddressRangeImpl(getStart(), getEnd());
}

bool MemoryBlock::contains(const Address& addr) const {
    return addr >= getStart() && addr <= getEnd() &&
           addr.hasSameAddressSpace(getStart());
}

bool MemoryBlock::isMapped() const {
    return getType() == MemoryBlockType::BIT_MAPPED ||
           getType() == MemoryBlockType::BYTE_MAPPED;
}

bool MemoryBlock::isExternalBlock() const {
    return getName() == EXTERNAL_BLOCK_NAME;
}

uint8_t MemoryBlock::getByte(const Address& addr) const {
    (void)addr;
    throw MemoryAccessException("getByte not implemented for this block type");
}

int MemoryBlock::getBytes(const Address& addr, uint8_t* buf, int len) const {
    (void)addr;
    (void)buf;
    (void)len;
    throw MemoryAccessException("getBytes not implemented for this block type");
}

void MemoryBlock::putByte(const Address& addr, uint8_t value) {
    (void)addr;
    (void)value;
    throw MemoryAccessException("putByte not allowed for this block type");
}

int MemoryBlock::putBytes(const Address& addr, const uint8_t* buf, int len) {
    (void)addr;
    (void)buf;
    (void)len;
    throw MemoryAccessException("putBytes not allowed for this block type");
}

std::vector<std::shared_ptr<MemoryBlockSourceInfo>> MemoryBlock::getSourceInfos() const {
    return {};
}

void MemoryBlock::setPermissions(bool read, bool write, bool execute) {
    setRead(read);
    setWrite(write);
    setExecute(execute);
}

int MemoryBlock::compareTo(const MemoryBlock& other) const {
    const Address& thisStart = getStart();
    const Address& otherStart = other.getStart();
    if (thisStart < otherStart) return -1;
    if (otherStart < thisStart) return 1;
    return 0;
}

} // namespace ghidra
