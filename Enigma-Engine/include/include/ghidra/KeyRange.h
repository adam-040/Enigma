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

namespace ghidra {

/**
 * Class for holding a range of database keys (64-bit unsigned values).
 */
class KeyRange {
public:
    uint64_t minKey;
    uint64_t maxKey;

    /**
     * Constructs a new key range.
     * @param minKey the min key (inclusive)
     * @param maxKey the max key (inclusive)
     */
    KeyRange(uint64_t min, uint64_t max) : minKey(min), maxKey(max) {}

    /**
     * Tests if the given key is in the range.
     * @param key the key to test
     * @return true if the key is in the range, false otherwise
     */
    bool contains(uint64_t key) const {
        return key >= minKey && key <= maxKey;
    }

    /**
     * Return the number of keys contained within range.
     * @return number of keys contained within range
     */
    uint64_t length() const {
        return maxKey - minKey + 1;
    }
};

} // namespace ghidra
