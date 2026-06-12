/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/MemBufferImageInputStream.h>
#include <algorithm>
#include <cstring>

namespace ghidra {

MemBufferImageInputStream::MemBufferImageInputStream(MemBuffer* buf)
    : buf_(buf), streamPos_(0) {}

int MemBufferImageInputStream::read() {
    try {
        uint8_t val = buf_->getUnsignedByte(static_cast<int>(streamPos_));
        streamPos_++;
        return val;
    } catch (...) {
        return -1;
    }
}

int MemBufferImageInputStream::read(uint8_t* b, int off, int len) {
    if (!b || len <= 0) return 0;
    std::vector<uint8_t> tmp(static_cast<size_t>(len));
    int n = buf_->getBytes(tmp, static_cast<int>(streamPos_));
    if (n <= 0) return -1;
    n = std::min(n, len);
    std::memcpy(b + off, tmp.data(), static_cast<size_t>(n));
    streamPos_ += n;
    return n;
}

} // namespace ghidra
