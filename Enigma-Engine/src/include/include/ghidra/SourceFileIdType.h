/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once
#include <cstdint>
#include <string>

namespace ghidra {

enum class SourceFileIdType : uint8_t {
    NONE = 0,
    UNKNOWN = 1,
    TIMESTAMP_64 = 2,
    MD5 = 3,
    SHA1 = 4,
    SHA256 = 5,
    SHA512 = 6
};

inline int getByteLength(SourceFileIdType type) {
    switch (type) {
        case SourceFileIdType::NONE: return 0;
        case SourceFileIdType::UNKNOWN: return 0;
        case SourceFileIdType::TIMESTAMP_64: return 8;
        case SourceFileIdType::MD5: return 16;
        case SourceFileIdType::SHA1: return 20;
        case SourceFileIdType::SHA256: return 32;
        case SourceFileIdType::SHA512: return 64;
    }
    return 0;
}

inline std::string toString(SourceFileIdType type) {
    switch (type) {
        case SourceFileIdType::NONE: return "NONE";
        case SourceFileIdType::UNKNOWN: return "UNKNOWN";
        case SourceFileIdType::TIMESTAMP_64: return "TIMESTAMP_64";
        case SourceFileIdType::MD5: return "MD5";
        case SourceFileIdType::SHA1: return "SHA1";
        case SourceFileIdType::SHA256: return "SHA256";
        case SourceFileIdType::SHA512: return "SHA512";
    }
    return "UNKNOWN";
}

} // namespace ghidra
