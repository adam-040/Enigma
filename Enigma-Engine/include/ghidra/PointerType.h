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
/// \file PointerType.h
/// \brief Specifies the pointer-type associated with a pointer-typedef
/// Translated from: ghidra.program.model.data.PointerType
#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

/**
 * PointerType specifies the pointer-type associated with a pointer-typedef.
 */
struct PointerType {
    int value;

    static const PointerType DEFAULT;
    static const PointerType IMAGE_BASE_RELATIVE;
    static const PointerType RELATIVE;
    static const PointerType FILE_OFFSET;

    constexpr PointerType(int v) : value(v) {}

    bool operator==(const PointerType& other) const { return value == other.value; }
    bool operator!=(const PointerType& other) const { return value != other.value; }

    static PointerType valueOf(int val) {
        if (val == DEFAULT.value) return DEFAULT;
        if (val == IMAGE_BASE_RELATIVE.value) return IMAGE_BASE_RELATIVE;
        if (val == RELATIVE.value) return RELATIVE;
        if (val == FILE_OFFSET.value) return FILE_OFFSET;
        throw std::out_of_range("unknown type value: " + std::to_string(val));
    }

    std::string name() const {
        if (value == DEFAULT.value) return "DEFAULT";
        if (value == IMAGE_BASE_RELATIVE.value) return "IMAGE_BASE_RELATIVE";
        if (value == RELATIVE.value) return "RELATIVE";
        if (value == FILE_OFFSET.value) return "FILE_OFFSET";
        return "UNKNOWN";
    }
};

inline const PointerType PointerType::DEFAULT(0);
inline const PointerType PointerType::IMAGE_BASE_RELATIVE(1);
inline const PointerType PointerType::RELATIVE(2);
inline const PointerType PointerType::FILE_OFFSET(3);

} // namespace ghidra
