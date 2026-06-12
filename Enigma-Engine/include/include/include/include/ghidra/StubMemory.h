/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file StubMemory.h
/// \brief Stub Memory backed by an AddressSet + byte array
/// Translated from: ghidra.program.model.mem.StubMemory
#pragma once

#include <ghidra/AddressSet.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlockStub.h>
#include <vector>
#include <cstdint>

namespace ghidra {

class StubMemory : public AddressSet, public Memory {
private:
    std::vector<uint8_t> bytes_;
    MemoryBlockStub block_;

public:
    StubMemory();
    explicit StubMemory(const std::vector<uint8_t>& bytes);

    bool isBigEndian() const override;
    long long getSize() const override;
    MemoryBlock* getBlock(const Address& addr) override;
    MemoryBlock* getBlock(const std::string& blockName) override;
    std::vector<MemoryBlock*> getBlocks() override;

    uint8_t getByte(const Address& addr) override;
    int getBytes(const Address& addr, uint8_t* dest, int size) override;
    void setByte(const Address& addr, uint8_t value) override;
    void setBytes(const Address& addr, const uint8_t* source, int size) override;

    uint16_t getShort(const Address& addr) override;
    uint16_t getShort(const Address& addr, bool bigEndian) override;
    uint32_t getInt(const Address& addr) override;
    uint32_t getInt(const Address& addr, bool bigEndian) override;
    uint64_t getLong(const Address& addr) override;
    uint64_t getLong(const Address& addr, bool bigEndian) override;
    void setShort(const Address& addr, uint16_t value) override;
    void setShort(const Address& addr, uint16_t value, bool bigEndian) override;
    void setInt(const Address& addr, uint32_t value) override;
    void setInt(const Address& addr, uint32_t value, bool bigEndian) override;
    void setLong(const Address& addr, uint64_t value) override;
    void setLong(const Address& addr, uint64_t value, bool bigEndian) override;
};

} // namespace ghidra
