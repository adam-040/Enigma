/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file MemoryBlockType.h
/// \brief Enumeration of memory block types
#pragma once

#include <string>

namespace ghidra {

/**
 * Enumeration of memory block types.
 * Translated from: ghidra.program.model.mem.MemoryBlockType
 */
enum class MemoryBlockType {
    DEFAULT,
    BIT_MAPPED,
    BYTE_MAPPED
};

inline std::string toString(MemoryBlockType type) {
    switch (type) {
        case MemoryBlockType::DEFAULT:     return "Default";
        case MemoryBlockType::BIT_MAPPED:  return "Bit Mapped";
        case MemoryBlockType::BYTE_MAPPED: return "Byte Mapped";
    }
    return "Unknown";
}

} // namespace ghidra
