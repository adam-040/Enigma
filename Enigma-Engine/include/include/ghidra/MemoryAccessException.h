/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file MemoryAccessException.h
/// \brief Exception thrown when memory access is not permitted or invalid
#pragma once

#include "UsrException.h"

namespace ghidra {

/**
 * An MemoryAccessException indicates that the attempted memory access 
 * is not permitted (i.e. Readable/Writeable) or out of bounds.
 * Translated from: ghidra.program.model.mem.MemoryAccessException
 */
class MemoryAccessException : public UsrException {
public:
    MemoryAccessException() : UsrException("Memory Access Exception") {}
    
    explicit MemoryAccessException(const std::string& msg) : UsrException(msg) {}

    // Constructor with cause can be simulated by appending to the message
    MemoryAccessException(const std::string& msg, const std::exception& cause)
        : UsrException(msg + " - Cause: " + cause.what()) {}
};

} // namespace ghidra
