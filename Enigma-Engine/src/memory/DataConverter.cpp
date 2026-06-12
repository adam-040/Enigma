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
#include "ghidra/DataConverter.h"

namespace ghidra {

// --- BigEndianDataConverter ---

int16_t BigEndianDataConverter::getShort(const uint8_t* b, int offset) const {
    return static_cast<int16_t>(
        (static_cast<uint16_t>(b[offset]) << 8) |
        static_cast<uint16_t>(b[offset + 1]));
}

int32_t BigEndianDataConverter::getInt(const uint8_t* b, int offset) const {
    return static_cast<int32_t>(
        (static_cast<uint32_t>(b[offset]) << 24) |
        (static_cast<uint32_t>(b[offset + 1]) << 16) |
        (static_cast<uint32_t>(b[offset + 2]) << 8) |
        static_cast<uint32_t>(b[offset + 3]));
}

int64_t BigEndianDataConverter::getLong(const uint8_t* b, int offset) const {
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

uint64_t BigEndianDataConverter::getValue(const uint8_t* b, int offset, int size) const {
    uint64_t val = 0;
    for (int i = 0; i < size; i++) {
        val = (val << 8) | static_cast<uint64_t>(b[offset + i]);
    }
    return val;
}

std::vector<uint8_t> BigEndianDataConverter::getBytes(const uint8_t* b, int offset, int size) const {
    return std::vector<uint8_t>(b + offset, b + offset + size);
}

void BigEndianDataConverter::putShort(uint8_t* b, int offset, int16_t value) const {
    uint16_t v = static_cast<uint16_t>(value);
    b[offset] = static_cast<uint8_t>(v >> 8);
    b[offset + 1] = static_cast<uint8_t>(v);
}

void BigEndianDataConverter::putInt(uint8_t* b, int offset, int32_t value) const {
    uint32_t v = static_cast<uint32_t>(value);
    b[offset] = static_cast<uint8_t>(v >> 24);
    b[offset + 1] = static_cast<uint8_t>(v >> 16);
    b[offset + 2] = static_cast<uint8_t>(v >> 8);
    b[offset + 3] = static_cast<uint8_t>(v);
}

void BigEndianDataConverter::putLong(uint8_t* b, int offset, int64_t value) const {
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

void BigEndianDataConverter::putValue(uint64_t value, int size, uint8_t* b, int offset) const {
    for (int i = size - 1; i >= 0; i--) {
        b[offset + i] = static_cast<uint8_t>(value & 0xff);
        value >>= 8;
    }
}

// --- LittleEndianDataConverter ---

int16_t LittleEndianDataConverter::getShort(const uint8_t* b, int offset) const {
    return static_cast<int16_t>(
        static_cast<uint16_t>(b[offset]) |
        (static_cast<uint16_t>(b[offset + 1]) << 8));
}

int32_t LittleEndianDataConverter::getInt(const uint8_t* b, int offset) const {
    return static_cast<int32_t>(
        static_cast<uint32_t>(b[offset]) |
        (static_cast<uint32_t>(b[offset + 1]) << 8) |
        (static_cast<uint32_t>(b[offset + 2]) << 16) |
        (static_cast<uint32_t>(b[offset + 3]) << 24));
}

int64_t LittleEndianDataConverter::getLong(const uint8_t* b, int offset) const {
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

uint64_t LittleEndianDataConverter::getValue(const uint8_t* b, int offset, int size) const {
    uint64_t val = 0;
    for (int i = size - 1; i >= 0; i--) {
        val = (val << 8) | static_cast<uint64_t>(b[offset + i]);
    }
    return val;
}

std::vector<uint8_t> LittleEndianDataConverter::getBytes(const uint8_t* b, int offset, int size) const {
    return std::vector<uint8_t>(b + offset, b + offset + size);
}

void LittleEndianDataConverter::putShort(uint8_t* b, int offset, int16_t value) const {
    uint16_t v = static_cast<uint16_t>(value);
    b[offset] = static_cast<uint8_t>(v);
    b[offset + 1] = static_cast<uint8_t>(v >> 8);
}

void LittleEndianDataConverter::putInt(uint8_t* b, int offset, int32_t value) const {
    uint32_t v = static_cast<uint32_t>(value);
    b[offset] = static_cast<uint8_t>(v);
    b[offset + 1] = static_cast<uint8_t>(v >> 8);
    b[offset + 2] = static_cast<uint8_t>(v >> 16);
    b[offset + 3] = static_cast<uint8_t>(v >> 24);
}

void LittleEndianDataConverter::putLong(uint8_t* b, int offset, int64_t value) const {
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

void LittleEndianDataConverter::putValue(uint64_t value, int size, uint8_t* b, int offset) const {
    for (int i = 0; i < size; i++) {
        b[offset + i] = static_cast<uint8_t>(value & 0xff);
        value >>= 8;
    }
}

// --- DataConverter static ---

const DataConverter* DataConverter::getConverter(bool isBigEndian) {
    static BigEndianDataConverter big;
    static LittleEndianDataConverter little;
    return isBigEndian ? static_cast<const DataConverter*>(&big) : static_cast<const DataConverter*>(&little);
}

} // namespace ghidra
