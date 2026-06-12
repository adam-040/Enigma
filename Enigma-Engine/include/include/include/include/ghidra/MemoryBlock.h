/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file MemoryBlock.h
/// \brief Interface that defines a block in memory
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include "Address.h"
#include "AddressRangeImpl.h"
#include "MemoryBlockType.h"
#include "MemoryAccessException.h"

namespace ghidra {

/// Forward declarations for database-dependent types
class FileBytes;

/**
 * Minimal stub for MemoryBlockSourceInfo.
 * Full implementation requires database layer.
 */
class MemoryBlockSourceInfo {
public:
    virtual ~MemoryBlockSourceInfo() = default;

    /// Returns the FileBytes associated with this source info, if any
    virtual std::shared_ptr<FileBytes> getFileBytes() const { return nullptr; }

    /// Locate the memory address corresponding to a file offset
    virtual Address locateAddressForFileOffset(long long fileOffset) const { return Address(); }
};

/**
 * Interface that defines a block in memory.
 * Translated from: ghidra.program.model.mem.MemoryBlock
 *
 * Memory blocks represent contiguous regions of memory with specific
 * permissions (read/write/execute) and attributes (volatile/artificial).
 *
 * Flag bits:
 *   EXECUTE    = 0x1
 *   WRITE      = 0x2
 *   READ       = 0x4
 *   VOLATILE   = 0x8
 *   ARTIFICIAL = 0x10
 */
class MemoryBlock {
public:
    /// Special purpose EXTERNAL block name used by certain program loaders
    static constexpr const char* EXTERNAL_BLOCK_NAME = "EXTERNAL";

    /// Memory block flag bits
    static constexpr int FLAG_EXECUTE    = 0x1;
    static constexpr int FLAG_WRITE      = 0x2;
    static constexpr int FLAG_READ       = 0x4;
    static constexpr int FLAG_VOLATILE   = 0x8;
    static constexpr int FLAG_ARTIFICIAL = 0x10;

    virtual ~MemoryBlock() = default;

    // --- Core address/size queries ---

    /// Return the starting address for this block
    virtual const Address& getStart() const = 0;

    /// Return the end address of this block (inclusive)
    virtual const Address& getEnd() const = 0;

    /// Get the address range that corresponds to this block
    virtual AddressRangeImpl getAddressRange() const;

    /// Get the number of bytes in this block
    virtual long long getSize() const = 0;

    /// Return whether addr is contained in this block
    virtual bool contains(const Address& addr) const;

    // --- Identity ---

    /// Get the name of this block
    virtual std::string getName() const = 0;

    /// Set the name for this block
    virtual void setName(const std::string& name) = 0;

    /// Get the comment associated with this block
    virtual std::string getComment() const = 0;

    /// Set the comment associated with this block
    virtual void setComment(const std::string& comment) = 0;

    /// Get the name of the source of this memory block
    virtual std::string getSourceName() const = 0;

    /// Set the name of the source file that provided the data
    virtual void setSourceName(const std::string& sourceName) = 0;

    // --- Permissions ---

    /// Returns block flags as a bit mask
    virtual int getFlags() const = 0;

    /// Returns the value of the read property
    virtual bool isRead() const { return (getFlags() & FLAG_READ) != 0; }

    /// Sets the read property
    virtual void setRead(bool r) = 0;

    /// Returns the value of the write property
    virtual bool isWrite() const { return (getFlags() & FLAG_WRITE) != 0; }

    /// Sets the write property
    virtual void setWrite(bool w) = 0;

    /// Returns the value of the execute property
    virtual bool isExecute() const { return (getFlags() & FLAG_EXECUTE) != 0; }

    /// Sets the execute property
    virtual void setExecute(bool e) = 0;

    /// Sets the read, write, execute permissions on this block
    virtual void setPermissions(bool read, bool write, bool execute);

    // --- Attributes ---

    /// Returns the volatile attribute state
    virtual bool isVolatile() const { return (getFlags() & FLAG_VOLATILE) != 0; }

    /// Sets the volatile attribute state
    virtual void setVolatile(bool v) = 0;

    /// Returns the artificial attribute state
    virtual bool isArtificial() const { return (getFlags() & FLAG_ARTIFICIAL) != 0; }

    /// Sets the artificial attribute state
    virtual void setArtificial(bool a) = 0;

    // --- Type & state ---

    /// Get the type for this block: DEFAULT, BIT_MAPPED, or BYTE_MAPPED
    virtual MemoryBlockType getType() const = 0;

    /// Return whether this block has been initialized
    virtual bool isInitialized() const = 0;

    /// Returns true if this is either a bit-mapped or byte-mapped block
    virtual bool isMapped() const;

    /// Returns true if this is a reserved EXTERNAL memory block based upon its name
    virtual bool isExternalBlock() const;

    /// Returns true if this is an overlay block
    virtual bool isOverlay() const = 0;

    /// Returns true if this memory block is a real loaded block
    virtual bool isLoaded() const = 0;

    // --- Byte access ---

    /// Returns the byte at the given address in this block
    virtual uint8_t getByte(const Address& addr) const;
    virtual int getBytes(const Address& addr, uint8_t* buf, int len) const;
    virtual void putByte(const Address& addr, uint8_t value);
    virtual int putBytes(const Address& addr, const uint8_t* buf, int len);

    // --- Source info ---

    /// Returns a list of MemoryBlockSourceInfo objects for this block
    virtual std::vector<std::shared_ptr<MemoryBlockSourceInfo>> getSourceInfos() const;

    // --- Comparison (Comparable<MemoryBlock>) ---

    /// Compare blocks by start address
    virtual int compareTo(const MemoryBlock& other) const;
    bool operator<(const MemoryBlock& other) const { return compareTo(other) < 0; }
    bool operator>(const MemoryBlock& other) const { return compareTo(other) > 0; }
    bool operator<=(const MemoryBlock& other) const { return compareTo(other) <= 0; }
    bool operator>=(const MemoryBlock& other) const { return compareTo(other) >= 0; }
    bool operator==(const MemoryBlock& other) const {
        return compareTo(other) == 0 && getName() == other.getName();
    }
    bool operator!=(const MemoryBlock& other) const { return !(*this == other); }
};

} // namespace ghidra
