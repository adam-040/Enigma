/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/PackedBytes.h"

namespace ghidra {

PackedBytes::PackedBytes(int startLen) : out_(startLen, 0), bytecnt_(0) {}

uint8_t PackedBytes::getByte(int streampos) const {
    return out_[streampos];
}

void PackedBytes::insertByte(int streampos, int val) {
    if (streampos < 0) return;
    if (streampos >= (int)out_.size()) {
        int newSize = std::max((int)out_.size() << 1, streampos + 1);
        if (newSize < 64) newSize = 64;
        out_.resize(newSize, 0);
    }
    out_[streampos] = (uint8_t)val;
    if (streampos >= bytecnt_) bytecnt_ = streampos + 1;
}

void PackedBytes::writeByte(int val) {
    int newcount = bytecnt_ + 1;
    if (newcount > (int)out_.size()) {
        out_.resize(std::max((int)out_.size() << 1, newcount), 0);
    }
    out_[bytecnt_] = (uint8_t)val;
    bytecnt_ = newcount;
}

void PackedBytes::writeBytes(const uint8_t* byteArray, int off, int len) {
    int newcount = bytecnt_ + len;
    if (newcount > (int)out_.size()) {
        out_.resize(std::max((int)out_.size() << 1, newcount), 0);
    }
    for (int i = 0; i < len; ++i) {
        out_[bytecnt_ + i] = byteArray[off + i];
    }
    bytecnt_ = newcount;
}

int PackedBytes::find(int start, int val) const {
    while (start < bytecnt_) {
        if (out_[start] == (uint8_t)val) {
            return start;
        }
        start += 1;
    }
    return -1;
}

void PackedBytes::writeTo(std::vector<uint8_t>& dst) const {
    dst.assign(out_.begin(), out_.begin() + bytecnt_);
}

} // namespace ghidra
