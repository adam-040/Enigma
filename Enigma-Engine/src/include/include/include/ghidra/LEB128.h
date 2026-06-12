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
#include <stdexcept>
#include <string>
#include <vector>

namespace ghidra {

class LEB128EncodeException : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class LEB128 {
public:
    static constexpr int MAX_SUPPORTED_LENGTH = 10;

    static int64_t signedDecode(const uint8_t* bytes, size_t offset, size_t length);
    static uint64_t unsignedDecode(const uint8_t* bytes, size_t offset, size_t length);
    static int64_t readDecode(const uint8_t* bytes, size_t offset, size_t length, bool isSigned);

    static int getLength(const uint8_t* bytes, size_t offset, size_t length);

    static std::vector<uint8_t> encode(int64_t value, bool isSigned);

    static std::vector<uint8_t> encodeSigned(int64_t value);
    static std::vector<uint8_t> encodeUnsigned(uint64_t value);
};

} // namespace ghidra
