/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 */
/// \file ObjectStorage.h
/// \brief Interface for object serialization storage
/// Translated from: ghidra.util.ObjectStorage
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ghidra {

class ObjectStorage {
public:
    virtual ~ObjectStorage() = default;

    virtual void putInt(int32_t value) = 0;
    virtual void putLong(int64_t value) = 0;
    virtual void putString(const std::string& value) = 0;
    virtual void putBytes(const std::vector<uint8_t>& value) = 0;
    virtual void putBoolean(bool value) = 0;
    virtual void putShort(int16_t value) = 0;
    virtual void putByte(uint8_t value) = 0;

    virtual int32_t getInt() = 0;
    virtual int64_t getLong() = 0;
    virtual std::string getString() = 0;
    virtual std::vector<uint8_t> getBytes() = 0;
    virtual bool getBoolean() = 0;
    virtual int16_t getShort() = 0;
    virtual uint8_t getByte() = 0;
};

} // namespace ghidra
