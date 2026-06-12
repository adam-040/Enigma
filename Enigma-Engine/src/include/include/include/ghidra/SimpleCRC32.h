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

struct SimpleCRC32 {
    static const uint32_t crc32tab[256];

    static int hashOneByte(int hashcode, int val) {
        return static_cast<int>(crc32tab[(hashcode ^ val) & 0xff] ^
                                (static_cast<uint32_t>(hashcode) >> 8));
    }
};

} // namespace ghidra
