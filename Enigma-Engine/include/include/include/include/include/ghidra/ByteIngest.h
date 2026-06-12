/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ByteIngest.h
/// \brief Ingest bytes from a stream in preparation for decoding.
#pragma once

#include <cstdint>
#include <istream>
#include <stdexcept>
#include <string>
#include <vector>

namespace ghidra {

/**
 * Object that can ingest bytes from a stream in preparation for decoding.
 * Translated from: ghidra.program.model.pcode.ByteIngest
 */
class ByteIngest {
public:
    virtual ~ByteIngest() = default;

    virtual void clear() = 0;
    virtual void open(int max, const std::string& desc) = 0;
    virtual void ingestStreamToNextTerminator(std::istream& in) = 0;
    virtual void ingestStream(std::istream& in) = 0;
    virtual void ingestBytes(const uint8_t* bytes, int off, int sz) = 0;
    virtual void endIngest() = 0;
    virtual bool isEmpty() const = 0;
};

} // namespace ghidra
