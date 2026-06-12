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
#include <unordered_set>

namespace ghidra {

class BitGroup {
public:
    explicit BitGroup(int64_t value)
        : mask_(value) {
        values_.insert(value);
    }

    bool intersects(const BitGroup& other) const {
        return (mask_ & other.mask_) != 0;
    }

    void merge(const BitGroup& other) {
        values_.insert(other.values_.begin(), other.values_.end());
        mask_ |= other.mask_;
    }

    int64_t getMask() const { return mask_; }

    const std::unordered_set<int64_t>& getValues() const { return values_; }

    std::string toString() const {
        std::string buf = "BitGroup - Mask: 0x" + int64ToHex(mask_) + " values: ";
        for (int64_t v : values_) {
            buf += std::to_string(v) + ",";
        }
        return buf;
    }

private:
    std::unordered_set<int64_t> values_;
    int64_t mask_;

    static std::string int64ToHex(int64_t v) {
        char tmp[19];
        std::snprintf(tmp, sizeof(tmp), "%llx", (unsigned long long)v);
        return std::string(tmp);
    }
};

} // namespace ghidra
