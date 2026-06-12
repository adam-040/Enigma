/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/// \file DataConverter.h
/// \brief Stateless helper for converting numeric types to/from byte arrays
/// Translated from: ghidra.util.DataConverter
#pragma once

#include <cstdint>
#include <vector>
#include <stdexcept>
#include <cstring>
#include "ghidra/Endian.h"

namespace ghidra {

/**
 * Stateless helper classes with static singleton instances that contain methods to convert
 * numeric types to and from their raw form in a byte array.
 */
class DataConverter {
public:
    virtual ~DataConverter() = default;

    /// Returns the endianness of this converter
    virtual bool isBigEndian() const = 0;

    // --- Read operations ---

    virtual int16_t getShort(const uint8_t* b, int offset) const = 0;
    virtual int32_t getInt(const uint8_t* b, int offset) const = 0;
    virtual int64_t getLong(const uint8_t* b, int offset) const = 0;

    /// Get unsigned value of specified size (1-8 bytes) as int64_t
    virtual uint64_t getValue(const uint8_t* b, int offset, int size) const = 0;

    /// Get signed value of specified size (1-8 bytes) as int64_t
    inline int64_t getSignedValue(const uint8_t* b, int offset, int size) const {
        uint64_t val = getValue(b, offset, size);
        int shiftBits = (8 - size) * 8;
        return static_cast<int64_t>(val << shiftBits) >> shiftBits;
    }

    /// Get bytes as a vector of the specified size
    virtual std::vector<uint8_t> getBytes(const uint8_t* b, int offset, int size) const = 0;

    // --- Write operations ---

    virtual void putShort(uint8_t* b, int offset, int16_t value) const = 0;
    virtual void putInt(uint8_t* b, int offset, int32_t value) const = 0;
    virtual void putLong(uint8_t* b, int offset, int64_t value) const = 0;

    /// Write value of specified size (1-8 bytes) to byte array
    virtual void putValue(uint64_t value, int size, uint8_t* b, int offset) const = 0;

    // --- Convenience wrappers ---

    inline int16_t getShort(const std::vector<uint8_t>& b) const { return getShort(b.data(), 0); }
    inline int16_t getShort(const std::vector<uint8_t>& b, int offset) const { return getShort(b.data(), offset); }
    inline int32_t getInt(const std::vector<uint8_t>& b) const { return getInt(b.data(), 0); }
    inline int32_t getInt(const std::vector<uint8_t>& b, int offset) const { return getInt(b.data(), offset); }
    inline int64_t getLong(const std::vector<uint8_t>& b) const { return getLong(b.data(), 0); }
    inline int64_t getLong(const std::vector<uint8_t>& b, int offset) const { return getLong(b.data(), offset); }
    inline uint64_t getValue(const std::vector<uint8_t>& b, int size) const { return getValue(b.data(), 0, size); }
    inline uint64_t getValue(const std::vector<uint8_t>& b, int offset, int size) const { return getValue(b.data(), offset, size); }
    inline int64_t getSignedValue(const std::vector<uint8_t>& b, int size) const { return getSignedValue(b.data(), 0, size); }
    inline int64_t getSignedValue(const std::vector<uint8_t>& b, int offset, int size) const { return getSignedValue(b.data(), offset, size); }

    inline std::vector<uint8_t> getBytes(int16_t value) const {
        std::vector<uint8_t> buf(2);
        putShort(buf.data(), 0, value);
        return buf;
    }
    inline std::vector<uint8_t> getBytes(int32_t value) const {
        std::vector<uint8_t> buf(4);
        putInt(buf.data(), 0, value);
        return buf;
    }
    inline std::vector<uint8_t> getBytes(int64_t value) const {
        std::vector<uint8_t> buf(8);
        putLong(buf.data(), 0, value);
        return buf;
    }

    inline void putShort(std::vector<uint8_t>& b, int16_t value) const { putShort(b.data(), 0, value); }
    inline void putShort(std::vector<uint8_t>& b, int offset, int16_t value) const { putShort(b.data(), offset, value); }
    inline void putInt(std::vector<uint8_t>& b, int32_t value) const { putInt(b.data(), 0, value); }
    inline void putInt(std::vector<uint8_t>& b, int offset, int32_t value) const { putInt(b.data(), offset, value); }
    inline void putLong(std::vector<uint8_t>& b, int64_t value) const { putLong(b.data(), 0, value); }
    inline void putLong(std::vector<uint8_t>& b, int offset, int64_t value) const { putLong(b.data(), offset, value); }
    inline void putValue(uint64_t value, int size, std::vector<uint8_t>& b, int offset) const { putValue(value, size, b.data(), offset); }

    /// Swap the least-significant bytes of a value
    static inline uint64_t swapBytes(uint64_t val, int size) {
        uint64_t res = 0;
        while (size > 0) {
            res <<= 8;
            res |= (val & 0xff);
            val >>= 8;
            size -= 1;
        }
        return res;
    }

    /// Get a converter for the given endianness
    static const DataConverter* getConverter(bool isBigEndian);
};

/// Big-endian data converter
class BigEndianDataConverter : public DataConverter {
public:
    inline bool isBigEndian() const override { return true; }

    int16_t getShort(const uint8_t* b, int offset) const override;
    int32_t getInt(const uint8_t* b, int offset) const override;
    int64_t getLong(const uint8_t* b, int offset) const override;
    uint64_t getValue(const uint8_t* b, int offset, int size) const override;
    std::vector<uint8_t> getBytes(const uint8_t* b, int offset, int size) const override;
    void putShort(uint8_t* b, int offset, int16_t value) const override;
    void putInt(uint8_t* b, int offset, int32_t value) const override;
    void putLong(uint8_t* b, int offset, int64_t value) const override;
    void putValue(uint64_t value, int size, uint8_t* b, int offset) const override;
};

/// Little-endian data converter
class LittleEndianDataConverter : public DataConverter {
public:
    inline bool isBigEndian() const override { return false; }

    int16_t getShort(const uint8_t* b, int offset) const override;
    int32_t getInt(const uint8_t* b, int offset) const override;
    int64_t getLong(const uint8_t* b, int offset) const override;
    uint64_t getValue(const uint8_t* b, int offset, int size) const override;
    std::vector<uint8_t> getBytes(const uint8_t* b, int offset, int size) const override;
    void putShort(uint8_t* b, int offset, int16_t value) const override;
    void putInt(uint8_t* b, int offset, int32_t value) const override;
    void putLong(uint8_t* b, int offset, int64_t value) const override;
    void putValue(uint64_t value, int size, uint8_t* b, int offset) const override;
};

} // namespace ghidra
