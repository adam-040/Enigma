/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file MemoryBlockStub.h
/// \brief Stub MemoryBlock for testing and placeholder use
/// Translated from: ghidra.program.model.mem.MemoryBlockStub
#pragma once

#include <ghidra/MemoryBlock.h>
#include <ghidra/Address.h>

namespace ghidra {

class MemoryBlockStub : public MemoryBlock {
private:
    Address start_;
    Address end_;

public:
    MemoryBlockStub();
    MemoryBlockStub(const Address& start, const Address& end);

    const Address& getStart() const override;
    const Address& getEnd() const override;
    AddressRangeImpl getAddressRange() const override;
    long long getSize() const override;
    bool contains(const Address& addr) const override;

    std::string getName() const override;
    void setName(const std::string& name) override;
    std::string getComment() const override;
    void setComment(const std::string& comment) override;
    std::string getSourceName() const override;
    void setSourceName(const std::string& sourceName) override;

    int getFlags() const override;
    void setRead(bool r) override;
    void setWrite(bool w) override;
    void setExecute(bool e) override;
    void setVolatile(bool v) override;
    void setArtificial(bool a) override;

    MemoryBlockType getType() const override;
    bool isInitialized() const override;
    bool isMapped() const override;
    bool isExternalBlock() const override;
    bool isOverlay() const override;
    bool isLoaded() const override;

    uint8_t getByte(const Address& addr) const override;
    int getBytes(const Address& addr, uint8_t* buf, int len) const override;
    void putByte(const Address& addr, uint8_t value) override;
    int putBytes(const Address& addr, const uint8_t* buf, int len) override;

    int compareTo(const MemoryBlock& other) const override;
};

} // namespace ghidra
