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
#include "ghidra/GhidraDataConverter.h"

namespace ghidra {

// --- GhidraBigEndianDataConverter ---

int16_t GhidraBigEndianDataConverter::getShort(const uint8_t* b, int offset) const {
    return static_cast<int16_t>(
        (static_cast<uint16_t>(b[offset]) << 8) |
        static_cast<uint16_t>(b[offset + 1]));
}

int32_t GhidraBigEndianDataConverter::getInt(const uint8_t* b, int offset) const {
    return static_cast<int32_t>(
        (static_cast<uint32_t>(b[offset]) << 24) |
        (static_cast<uint32_t>(b[offset + 1]) << 16) |
        (static_cast<uint32_t>(b[offset + 2]) << 8) |
        static_cast<uint32_t>(b[offset + 3]));
}

int64_t GhidraBigEndianDataConverter::getLong(const uint8_t* b, int offset) const {
    return static_cast<int64_t>(
        (static_cast<uint64_t>(b[offset]) << 56) |
        (static_cast<uint64_t>(b[offset + 1]) << 48) |
        (static_cast<uint64_t>(b[offset + 2]) << 40) |
        (static_cast<uint64_t>(b[offset + 3]) << 32) |
        (static_cast<uint64_t>(b[offset + 4]) << 24) |
        (static_cast<uint64_t>(b[offset + 5]) << 16) |
        (static_cast<uint64_t>(b[offset + 6]) << 8) |
        static_cast<uint64_t>(b[offset + 7]));
}

uint64_t GhidraBigEndianDataConverter::getValue(const uint8_t* b, int offset, int size) const {
    uint64_t val = 0;
    for (int i = 0; i < size; i++) {
        val = (val << 8) | static_cast<uint64_t>(b[offset + i]);
    }
    return val;
}

std::vector<uint8_t> GhidraBigEndianDataConverter::getBytes(const uint8_t* b, int offset, int size) const {
    return std::vector<uint8_t>(b + offset, b + offset + size);
}

void GhidraBigEndianDataConverter::putShort(uint8_t* b, int offset, int16_t value) const {
    uint16_t v = static_cast<uint16_t>(value);
    b[offset] = static_cast<uint8_t>(v >> 8);
    b[offset + 1] = static_cast<uint8_t>(v);
}

void GhidraBigEndianDataConverter::putInt(uint8_t* b, int offset, int32_t value) const {
    uint32_t v = static_cast<uint32_t>(value);
    b[offset] = static_cast<uint8_t>(v >> 24);
    b[offset + 1] = static_cast<uint8_t>(v >> 16);
    b[offset + 2] = static_cast<uint8_t>(v >> 8);
    b[offset + 3] = static_cast<uint8_t>(v);
}

void GhidraBigEndianDataConverter::putLong(uint8_t* b, int offset, int64_t value) const {
    uint64_t v = static_cast<uint64_t>(value);
    b[offset] = static_cast<uint8_t>(v >> 56);
    b[offset + 1] = static_cast<uint8_t>(v >> 48);
    b[offset + 2] = static_cast<uint8_t>(v >> 40);
    b[offset + 3] = static_cast<uint8_t>(v >> 32);
    b[offset + 4] = static_cast<uint8_t>(v >> 24);
    b[offset + 5] = static_cast<uint8_t>(v >> 16);
    b[offset + 6] = static_cast<uint8_t>(v >> 8);
    b[offset + 7] = static_cast<uint8_t>(v);
}

void GhidraBigEndianDataConverter::putValue(uint64_t value, int size, uint8_t* b, int offset) const {
    for (int i = size - 1; i >= 0; i--) {
        b[offset + i] = static_cast<uint8_t>(value & 0xff);
        value >>= 8;
    }
}

int16_t GhidraBigEndianDataConverter::getShort(const MemBuffer* buf, int offset) const {
    std::vector<uint8_t> bytes(2);
    int read = buf->getBytes(bytes, offset);
    if (read < 2) throw MemoryAccessException("Failed to read 2 bytes at offset " + std::to_string(offset));
    return getShort(bytes.data(), 0);
}

int32_t GhidraBigEndianDataConverter::getInt(const MemBuffer* buf, int offset) const {
    std::vector<uint8_t> bytes(4);
    int read = buf->getBytes(bytes, offset);
    if (read < 4) throw MemoryAccessException("Failed to read 4 bytes at offset " + std::to_string(offset));
    return getInt(bytes.data(), 0);
}

int64_t GhidraBigEndianDataConverter::getLong(const MemBuffer* buf, int offset) const {
    std::vector<uint8_t> bytes(8);
    int read = buf->getBytes(bytes, offset);
    if (read < 8) throw MemoryAccessException("Failed to read 8 bytes at offset " + std::to_string(offset));
    return getLong(bytes.data(), 0);
}

std::vector<uint8_t> GhidraBigEndianDataConverter::getBigInteger(const MemBuffer* buf, int offset, int size, bool signed_val) const {
    (void)signed_val;
    std::vector<uint8_t> bytes(size);
    int read = buf->getBytes(bytes, offset);
    if (read < size) throw MemoryAccessException("Failed to read " + std::to_string(size) + " bytes at offset " + std::to_string(offset));
    return bytes;
}

// --- GhidraLittleEndianDataConverter ---

int16_t GhidraLittleEndianDataConverter::getShort(const uint8_t* b, int offset) const {
    return static_cast<int16_t>(
        static_cast<uint16_t>(b[offset]) |
        (static_cast<uint16_t>(b[offset + 1]) << 8));
}

int32_t GhidraLittleEndianDataConverter::getInt(const uint8_t* b, int offset) const {
    return static_cast<int32_t>(
        static_cast<uint32_t>(b[offset]) |
        (static_cast<uint32_t>(b[offset + 1]) << 8) |
        (static_cast<uint32_t>(b[offset + 2]) << 16) |
        (static_cast<uint32_t>(b[offset + 3]) << 24));
}

int64_t GhidraLittleEndianDataConverter::getLong(const uint8_t* b, int offset) const {
    return static_cast<int64_t>(
        static_cast<uint64_t>(b[offset]) |
        (static_cast<uint64_t>(b[offset + 1]) << 8) |
        (static_cast<uint64_t>(b[offset + 2]) << 16) |
        (static_cast<uint64_t>(b[offset + 3]) << 24) |
        (static_cast<uint64_t>(b[offset + 4]) << 32) |
        (static_cast<uint64_t>(b[offset + 5]) << 40) |
        (static_cast<uint64_t>(b[offset + 6]) << 48) |
        (static_cast<uint64_t>(b[offset + 7]) << 56));
}

uint64_t GhidraLittleEndianDataConverter::getValue(const uint8_t* b, int offset, int size) const {
    uint64_t val = 0;
    for (int i = size - 1; i >= 0; i--) {
        val = (val << 8) | static_cast<uint64_t>(b[offset + i]);
    }
    return val;
}

std::vector<uint8_t> GhidraLittleEndianDataConverter::getBytes(const uint8_t* b, int offset, int size) const {
    return std::vector<uint8_t>(b + offset, b + offset + size);
}

void GhidraLittleEndianDataConverter::putShort(uint8_t* b, int offset, int16_t value) const {
    uint16_t v = static_cast<uint16_t>(value);
    b[offset] = static_cast<uint8_t>(v);
    b[offset + 1] = static_cast<uint8_t>(v >> 8);
}

void GhidraLittleEndianDataConverter::putInt(uint8_t* b, int offset, int32_t value) const {
    uint32_t v = static_cast<uint32_t>(value);
    b[offset] = static_cast<uint8_t>(v);
    b[offset + 1] = static_cast<uint8_t>(v >> 8);
    b[offset + 2] = static_cast<uint8_t>(v >> 16);
    b[offset + 3] = static_cast<uint8_t>(v >> 24);
}

void GhidraLittleEndianDataConverter::putLong(uint8_t* b, int offset, int64_t value) const {
    uint64_t v = static_cast<uint64_t>(value);
    b[offset] = static_cast<uint8_t>(v);
    b[offset + 1] = static_cast<uint8_t>(v >> 8);
    b[offset + 2] = static_cast<uint8_t>(v >> 16);
    b[offset + 3] = static_cast<uint8_t>(v >> 24);
    b[offset + 4] = static_cast<uint8_t>(v >> 32);
    b[offset + 5] = static_cast<uint8_t>(v >> 40);
    b[offset + 6] = static_cast<uint8_t>(v >> 48);
    b[offset + 7] = static_cast<uint8_t>(v >> 56);
}

void GhidraLittleEndianDataConverter::putValue(uint64_t value, int size, uint8_t* b, int offset) const {
    for (int i = 0; i < size; i++) {
        b[offset + i] = static_cast<uint8_t>(value & 0xff);
        value >>= 8;
    }
}

int16_t GhidraLittleEndianDataConverter::getShort(const MemBuffer* buf, int offset) const {
    std::vector<uint8_t> bytes(2);
    int read = buf->getBytes(bytes, offset);
    if (read < 2) throw MemoryAccessException("Failed to read 2 bytes at offset " + std::to_string(offset));
    return getShort(bytes.data(), 0);
}

int32_t GhidraLittleEndianDataConverter::getInt(const MemBuffer* buf, int offset) const {
    std::vector<uint8_t> bytes(4);
    int read = buf->getBytes(bytes, offset);
    if (read < 4) throw MemoryAccessException("Failed to read 4 bytes at offset " + std::to_string(offset));
    return getInt(bytes.data(), 0);
}

int64_t GhidraLittleEndianDataConverter::getLong(const MemBuffer* buf, int offset) const {
    std::vector<uint8_t> bytes(8);
    int read = buf->getBytes(bytes, offset);
    if (read < 8) throw MemoryAccessException("Failed to read 8 bytes at offset " + std::to_string(offset));
    return getLong(bytes.data(), 0);
}

std::vector<uint8_t> GhidraLittleEndianDataConverter::getBigInteger(const MemBuffer* buf, int offset, int size, bool signed_val) const {
    (void)signed_val;
    std::vector<uint8_t> bytes(size);
    int read = buf->getBytes(bytes, offset);
    if (read < size) throw MemoryAccessException("Failed to read " + std::to_string(size) + " bytes at offset " + std::to_string(offset));
    return bytes;
}

// --- GhidraDataConverter static ---

const GhidraDataConverter* GhidraDataConverter::getConverter(bool isBigEndian) {
    static GhidraBigEndianDataConverter big;
    static GhidraLittleEndianDataConverter little;
    return isBigEndian ? static_cast<const GhidraDataConverter*>(&big) : static_cast<const GhidraDataConverter*>(&little);
}

} // namespace ghidra
