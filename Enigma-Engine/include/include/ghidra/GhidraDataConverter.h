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
/// \file GhidraDataConverter.h
/// \brief DataConverter extension that reads from MemBuffer
/// Translated from: ghidra.util.GhidraDataConverter
#pragma once

#include <cstdint>
#include <vector>
#include "ghidra/DataConverter.h"
#include "ghidra/MemBuffer.h"
#include "ghidra/MemoryAccessException.h"

namespace ghidra {

/**
 * GhidraDataConverter extends DataConverter with methods that read directly from MemBuffer.
 */
class GhidraDataConverter : public DataConverter {
public:
    virtual ~GhidraDataConverter() = default;

    /// Read a short from MemBuffer at offset
    virtual int16_t getShort(const MemBuffer* buf, int offset) const = 0;

    /// Read an int from MemBuffer at offset
    virtual int32_t getInt(const MemBuffer* buf, int offset) const = 0;

    /// Read a long from MemBuffer at offset
    virtual int64_t getLong(const MemBuffer* buf, int offset) const = 0;

    /// Read a BigInteger (byte vector) from MemBuffer at offset
    virtual std::vector<uint8_t> getBigInteger(const MemBuffer* buf, int offset, int size, bool signed_val) const = 0;

    /// Get a converter for the given endianness
    static const GhidraDataConverter* getConverter(bool isBigEndian);
};

/// Big-endian Ghidra data converter
class GhidraBigEndianDataConverter : public GhidraDataConverter {
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

    int16_t getShort(const MemBuffer* buf, int offset) const override;
    int32_t getInt(const MemBuffer* buf, int offset) const override;
    int64_t getLong(const MemBuffer* buf, int offset) const override;
    std::vector<uint8_t> getBigInteger(const MemBuffer* buf, int offset, int size, bool signed_val) const override;
};

/// Little-endian Ghidra data converter
class GhidraLittleEndianDataConverter : public GhidraDataConverter {
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

    int16_t getShort(const MemBuffer* buf, int offset) const override;
    int32_t getInt(const MemBuffer* buf, int offset) const override;
    int64_t getLong(const MemBuffer* buf, int offset) const override;
    std::vector<uint8_t> getBigInteger(const MemBuffer* buf, int offset, int size, bool signed_val) const override;
};

} // namespace ghidra
