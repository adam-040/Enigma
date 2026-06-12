/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file MemBuffer.h
/// \brief Array-like interface into memory at a specific address
#pragma once

#include <vector>
#include <cstdint>
#include <istream>
#include <memory>
#include "Address.h"
#include "MemoryAccessException.h"

namespace ghidra {

class Memory; // Forward declaration

/**
 * MemBuffer provides an array-like interface into memory at a specific address.
 * Translated from: ghidra.program.model.mem.MemBuffer
 */
class MemBuffer {
public:
    virtual ~MemBuffer() = default;

    virtual bool isInitializedMemory() const {
        try {
            getByte(0);
            return true;
        } catch (const MemoryAccessException&) {
            return false;
        }
    }

    virtual int8_t getByte(int offset) const = 0;

    virtual uint8_t getUnsignedByte(int offset) const {
        return static_cast<uint8_t>(getByte(offset));
    }

    virtual int getBytes(std::vector<uint8_t>& b, int offset) const = 0;
    virtual int getBytes(uint8_t* b, int length, int offset) const = 0;

    virtual Address getAddress() const = 0;

    virtual Memory* getMemory() const = 0;

    virtual bool isBigEndian() const = 0;

    virtual int16_t getShort(int offset) const = 0;

    virtual uint16_t getUnsignedShort(int offset) const {
        return static_cast<uint16_t>(getShort(offset));
    }

    virtual int32_t getInt(int offset) const = 0;

    virtual uint32_t getUnsignedInt(int offset) const {
        return static_cast<uint32_t>(getInt(offset));
    }

    virtual int64_t getLong(int offset) const = 0;

    virtual std::vector<uint8_t> getBigInteger(int offset, int size, bool signed_val) const = 0;

    virtual int32_t getVarLengthInt(int offset, int len) const {
        switch (len) {
            case 1: return getByte(offset);
            case 2: return getShort(offset);
            case 4: return getInt(offset);
            default: throw MemoryAccessException("Invalid length for read: " + std::to_string(len));
        }
    }

    virtual uint32_t getVarLengthUnsignedInt(int offset, int len) const {
        switch (len) {
            case 1: return getUnsignedByte(offset);
            case 2: return getUnsignedShort(offset);
            case 4: return getUnsignedInt(offset);
            default: throw MemoryAccessException("Invalid length for read: " + std::to_string(len));
        }
    }

    virtual std::unique_ptr<std::istream> getInputStream() const = 0;
    virtual std::unique_ptr<std::istream> getInputStream(int initialPosition, int length) const = 0;
};

} // namespace ghidra
