/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/LEB128.h>
#include <vector>
#include <stdexcept>

namespace ghidra {

int64_t LEB128::readDecode(const uint8_t* bytes, size_t offset, size_t length, bool isSigned) {
    int shift = 0;
    int64_t value = 0;
    size_t pos = offset;
    while (true) {
        if (pos >= offset + length) {
            throw LEB128EncodeException("Unexpected end of LEB128 data");
        }
        int nextByte = bytes[pos++];
        if (shift == 70 || (!isSigned && shift == 63 && nextByte > 1)) {
            throw LEB128EncodeException("Unsupported LEB128 value, too large for 64-bit");
        }
        value |= (static_cast<int64_t>(nextByte & 0x7F)) << shift;
        shift += 7;
        if ((nextByte & 0x80) == 0) {
            break;
        }
    }
    if (isSigned && shift < 64 && ((bytes[pos - 1] & 0x40) != 0)) {
        value |= (-1LL << shift);
    }
    return value;
}

int64_t LEB128::signedDecode(const uint8_t* bytes, size_t offset, size_t length) {
    return readDecode(bytes, offset, length, true);
}

uint64_t LEB128::unsignedDecode(const uint8_t* bytes, size_t offset, size_t length) {
    return static_cast<uint64_t>(readDecode(bytes, offset, length, false));
}

int LEB128::getLength(const uint8_t* bytes, size_t offset, size_t length) {
    int len = 0;
    size_t pos = offset;
    while (pos < offset + length && len < MAX_SUPPORTED_LENGTH) {
        int nextByte = bytes[pos++];
        len++;
        if ((nextByte & 0x80) == 0) {
            return len;
        }
    }
    return -1;
}

std::vector<uint8_t> LEB128::encode(int64_t value, bool isSigned) {
    return isSigned ? encodeSigned(value) : encodeUnsigned(static_cast<uint64_t>(value));
}

std::vector<uint8_t> LEB128::encodeSigned(int64_t value) {
    std::vector<uint8_t> result;
    result.reserve(MAX_SUPPORTED_LENGTH);
    int64_t endingVal = value < 0 ? -1 : 0;
    int hiBit = value < 0 ? 0x40 : 0;
    bool more;
    do {
        int b = static_cast<int>(value & 0x7f);
        value >>= 7;
        more = value != endingVal || ((b & 0x40) != hiBit);
        if (more) {
            b |= 0x80;
        }
        result.push_back(static_cast<uint8_t>(b));
    } while (more);
    return result;
}

std::vector<uint8_t> LEB128::encodeUnsigned(uint64_t value) {
    std::vector<uint8_t> result;
    result.reserve(MAX_SUPPORTED_LENGTH);
    bool done;
    do {
        int b = static_cast<int>(value & 0x7f);
        value >>= 7;
        done = value == 0;
        if (!done) {
            b |= 0x80;
        }
        result.push_back(static_cast<uint8_t>(b));
    } while (!done);
    return result;
}

} // namespace ghidra
