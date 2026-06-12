/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Memory.h
/// \brief Memory model facade for managing memory blocks
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <algorithm>
#include <cstring>
#include <stdexcept>
#include "Address.h"
#include "MemoryBlock.h"
#include "MemoryBlockType.h"
#include "MemoryAccessException.h"
#include "Endian.h"

namespace ghidra {

/// Forward declaration
class ByteMappingScheme;

/**
 * Memory interface for managing memory blocks.
 * Translated from: ghidra.program.model.mem.Memory
 *
 * Provides the ability to inspect and manage the memory model,
 * including block creation, retrieval, and byte-level access.
 */
class Memory {
public:
    static constexpr int GBYTE_SHIFT_FACTOR = 30;
    static constexpr long long GBYTE = 1LL << GBYTE_SHIFT_FACTOR;
    static constexpr int MAX_BINARY_SIZE_GB = 16;
    static constexpr long long MAX_BINARY_SIZE = (long long)MAX_BINARY_SIZE_GB << GBYTE_SHIFT_FACTOR;
    static constexpr int MAX_BLOCK_SIZE_GB = 16;
    static constexpr long long MAX_BLOCK_SIZE = (long long)MAX_BLOCK_SIZE_GB << GBYTE_SHIFT_FACTOR;

    virtual ~Memory() = default;

    /// Returns true if the memory is big endian
    virtual bool isBigEndian() const = 0;

    /// Get the total memory size in bytes (sum of all block sizes)
    virtual long long getSize() const = 0;

    /// Returns the Block which contains addr, or nullptr if not found
    virtual MemoryBlock* getBlock(const Address& addr) = 0;

    /// Returns the Block with the specified name, or nullptr if not found
    virtual MemoryBlock* getBlock(const std::string& blockName) = 0;

    /// Returns a vector containing all the memory blocks
    virtual std::vector<MemoryBlock*> getBlocks() = 0;

    /// Validate the given block name
    static bool isValidMemoryBlockName(const std::string& name);

    /// Determine if the specified address is contained within the reserved EXTERNAL block
    virtual bool isExternalBlockAddress(const Address& addr);

    // --- Byte access ---

    virtual uint8_t getByte(const Address& addr);
    virtual int getBytes(const Address& addr, uint8_t* dest, int size);
    virtual void setByte(const Address& addr, uint8_t value);
    virtual void setBytes(const Address& addr, const uint8_t* source, int size);

    // --- Multi-byte access with endianness ---

    virtual uint16_t getShort(const Address& addr);
    virtual uint16_t getShort(const Address& addr, bool bigEndian);
    virtual uint32_t getInt(const Address& addr);
    virtual uint32_t getInt(const Address& addr, bool bigEndian);
    virtual uint64_t getLong(const Address& addr);
    virtual uint64_t getLong(const Address& addr, bool bigEndian);
    virtual void setShort(const Address& addr, uint16_t value);
    virtual void setShort(const Address& addr, uint16_t value, bool bigEndian);
    virtual void setInt(const Address& addr, uint32_t value);
    virtual void setInt(const Address& addr, uint32_t value, bool bigEndian);
    virtual void setLong(const Address& addr, uint64_t value);
    virtual void setLong(const Address& addr, uint64_t value, bool bigEndian);
};

/**
 * Concrete implementation of MemoryBlock for default (non-mapped) blocks.
 * Stores data in a contiguous byte array.
 */
class DefaultMemoryBlock : public MemoryBlock {
private:
    Address start_;
    Address end_;
    std::string name_;
    std::string comment_;
    std::string sourceName_;
    int flags_;
    bool initialized_;
    bool overlay_;
    bool loaded_;
    std::vector<uint8_t> data_;

public:
    DefaultMemoryBlock(const std::string& name, const Address& start, long long size,
                       bool initialized, uint8_t initialValue = 0,
                       bool overlay = false, bool loaded = true);

    const Address& getStart() const override;
    const Address& getEnd() const override;
    long long getSize() const override;
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
    bool isOverlay() const override;
    bool isLoaded() const override;
    uint8_t getByte(const Address& addr) const override;
    int getBytes(const Address& addr, uint8_t* buf, int len) const override;
    void putByte(const Address& addr, uint8_t value) override;
    int putBytes(const Address& addr, const uint8_t* buf, int len) override;
};

/**
 * Concrete implementation of Memory using a map of blocks.
 * Provides basic block management and byte-level access.
 */
class DefaultMemory : public Memory {
private:
    std::vector<std::unique_ptr<DefaultMemoryBlock>> blocks_;
    bool bigEndian_;
    int findBlockIndex(const Address& addr);

public:
    explicit DefaultMemory(bool bigEndian = true);
    bool isBigEndian() const override;
    long long getSize() const override;
    MemoryBlock* getBlock(const Address& addr) override;
    MemoryBlock* getBlock(const std::string& blockName) override;
    std::vector<MemoryBlock*> getBlocks() override;
    DefaultMemoryBlock* createInitializedBlock(const std::string& name, const Address& start,
                                                long long size, bool overlay = false);
    DefaultMemoryBlock* createInitializedBlock(const std::string& name, const Address& start,
                                                long long size, uint8_t initialValue,
                                                bool overlay = false);
    DefaultMemoryBlock* createUninitializedBlock(const std::string& name, const Address& start,
                                                  long long size, bool overlay = false);
    bool removeBlock(MemoryBlock* block);
    bool removeBlock(const std::string& name);
};

} // namespace ghidra
