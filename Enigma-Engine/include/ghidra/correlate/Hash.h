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
#include <functional>

namespace ghidra {

class Hash {
public:
    static const int SEED = 22222;
    static const int ALTERNATE_SEED = 11111;

    int value;
    int size;

    Hash() : value(0), size(0) {}
    Hash(int val, int sz) : value(val), size(sz) {}

    bool operator==(const Hash& o) const {
        return value == o.value && size == o.size;
    }
    bool operator!=(const Hash& o) const { return !(*this == o); }
    bool operator<(const Hash& o) const {
        if (value != o.value) return value < o.value;
        return size < o.size;
    }
};

} // namespace ghidra

namespace std {
    template<> struct hash<ghidra::Hash> {
        size_t operator()(const ghidra::Hash& h) const { return static_cast<size_t>(h.value); }
    };
}
