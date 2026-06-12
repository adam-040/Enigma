#pragma once

#include <cstdint>
#include <vector>

namespace ghidra {

inline uint64_t readULEB128(const uint8_t* data, int& pos, int maxSize) {
    uint64_t result = 0;
    int shift = 0;
    while (pos < maxSize) {
        uint8_t byte = data[pos++];
        result |= static_cast<uint64_t>(byte & 0x7F) << shift;
        shift += 7;
        if (!(byte & 0x80)) break;
    }
    return result;
}

inline int64_t readSLEB128(const uint8_t* data, int& pos, int maxSize) {
    int64_t result = 0;
    int shift = 0;
    uint8_t byte;
    do {
        if (pos >= maxSize) break;
        byte = data[pos++];
        result |= static_cast<int64_t>(byte & 0x7F) << shift;
        shift += 7;
    } while (byte & 0x80);
    if (shift < 64 && (byte & 0x40)) {
        result |= -(1LL << shift);
    }
    return result;
}

inline int writeULEB128(std::vector<uint8_t>& out, uint64_t value) {
    int count = 0;
    do {
        uint8_t byte = static_cast<uint8_t>(value & 0x7F);
        value >>= 7;
        if (value != 0) byte |= 0x80;
        out.push_back(byte);
        ++count;
    } while (value != 0);
    return count;
}

inline int writeSLEB128(std::vector<uint8_t>& out, int64_t value) {
    int count = 0;
    bool more = true;
    while (more) {
        uint8_t byte = static_cast<uint8_t>(value & 0x7F);
        value >>= 7;
        if ((value == 0 && !(byte & 0x40)) || (value == -1 && (byte & 0x40))) {
            more = false;
        } else {
            byte |= 0x80;
        }
        out.push_back(byte);
        ++count;
    }
    return count;
}

inline int encodedULEB128Size(uint64_t value) {
    int count = 0;
    do {
        value >>= 7;
        ++count;
    } while (value != 0);
    return count;
}

inline int encodedSLEB128Size(int64_t value) {
    int count = 0;
    bool more = true;
    while (more) {
        int64_t byte = value & 0x7F;
        value >>= 7;
        if ((value == 0 && !(byte & 0x40)) || (value == -1 && (byte & 0x40))) {
            more = false;
        } else {
            byte |= 0x80;
        }
        ++count;
    }
    return count;
}

} // namespace ghidra
