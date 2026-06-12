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

#include <ghidra/BitGroup.h>
#include <cstdint>
#include <vector>
#include <list>

namespace ghidra {

class EnumValuePartitioner {
public:
    static std::vector<BitGroup> partition(const std::vector<int64_t>& values, int size) {
        std::list<BitGroup> list;
        int64_t usedBits = 0;
        for (int64_t value : values) {
            usedBits |= value;
            BitGroup bg(value);
            merge(list, bg);
        }
        int bits = size * 8;
        int64_t allEnumBits = ~(-1LL << bits);
        int64_t unusedBits = ~usedBits;
        list.emplace_back(unusedBits & allEnumBits);
        return std::vector<BitGroup>(list.begin(), list.end());
    }

private:
    static void merge(std::list<BitGroup>& list, BitGroup& bitGroup) {
        for (auto it = list.begin(); it != list.end(); ) {
            if (bitGroup.intersects(*it)) {
                bitGroup.merge(*it);
                it = list.erase(it);
            } else {
                ++it;
            }
        }
        list.push_back(bitGroup);
    }
};

} // namespace ghidra
