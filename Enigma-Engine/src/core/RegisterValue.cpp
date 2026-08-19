/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file RegisterValue.cpp
/// \brief Register value implementation
#include <ghidra/RegisterValue.h>

namespace ghidra {

RegisterValue::RegisterValue() : reg_(nullptr) {}

RegisterValue::RegisterValue(Register* reg, const std::vector<uint8_t>& value)
    : reg_(reg), value_(value) {}

RegisterValue::RegisterValue(Register* reg, const std::vector<uint8_t>& value,
                             const std::vector<uint8_t>& mask)
    : reg_(reg), value_(value), mask_(mask) {}

RegisterValue::RegisterValue(Register* reg, uint64_t value, int size)
    : reg_(reg) {
    value_.resize(size);
    // A set value implies every byte is known-valid (Ghidra semantics);
    // round-trips through storage keep the full mask.
    mask_.assign(static_cast<size_t>(size), 0xFF);
    for (int i = 0; i < size; ++i) {
        value_[i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFF);
    }
}

uint64_t RegisterValue::getUnsignedOffset() const {
    uint64_t result = 0;
    for (size_t i = 0; i < value_.size() && i < 8; ++i) {
        result |= static_cast<uint64_t>(value_[i]) << (i * 8);
    }
    return result;
}

int64_t RegisterValue::getSignedOffset() const {
    uint64_t u = getUnsignedOffset();
    int bits = static_cast<int>(value_.size()) * 8;
    if (bits > 0 && bits < 64 && (u & (1ULL << (bits - 1)))) {
        return static_cast<int64_t>(u | (~0ULL << bits));
    }
    return static_cast<int64_t>(u);
}

} // namespace ghidra
