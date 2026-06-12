/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PackedBytes.h
/// \brief Dynamic byte buffer for packed encoding with edit support
/// Translated from: ghidra.program.model.pcode.PackedBytes
#pragma once

#include <cstdint>
#include <cstdio>
#include <vector>

namespace ghidra {

/// Dynamic byte buffer that supports in-place editing via insertByte().
/// Used by PackedEncode and PatchPackedEncode.
class PackedBytes {
private:
    std::vector<uint8_t> out_;
    int bytecnt_;

public:
    explicit PackedBytes(int startLen = 512);
    ~PackedBytes() = default;

    int size() const { return bytecnt_; }
    uint8_t getByte(int streampos) const;
    void insertByte(int streampos, int val);

    void writeByte(int val);
    void writeBytes(const uint8_t* byteArray, int off, int len);

    int find(int start, int val) const;
    void writeTo(std::vector<uint8_t>& dst) const;
};

} // namespace ghidra
