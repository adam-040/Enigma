/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/// \file AddressUtils.h
/// \brief Static utility functions for address arithmetic
/// Translated from: ghidra.pcodeCPort.address.AddressUtils
#pragma once

#include <cstdint>

namespace ghidra {

class AddressUtils {
private:
    AddressUtils() = delete;

public:
    static int unsignedCompare(int64_t v1, int64_t v2);
    static uint64_t unsignedSubtract(uint64_t a, uint64_t b);
    static uint64_t unsignedAdd(uint64_t a, uint64_t b);
};

} // namespace ghidra
