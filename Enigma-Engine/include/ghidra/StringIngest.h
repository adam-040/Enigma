/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file StringIngest.h
/// \brief ByteIngest implementation that ingests into an in-memory byte buffer.
#pragma once

#include "ghidra/ByteIngest.h"
#include <cstdint>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace ghidra {

/**
 * A ByteIngest that reads bytes from a stream until a 0-byte terminator (or up to maxBytes)
 * into an in-memory buffer.
 * Translated from: ghidra.program.model.pcode.StringIngest
 */
class StringIngest : public ByteIngest {
public:
    StringIngest();

    void open(int max, const std::string& desc) override;
    void ingestStreamToNextTerminator(std::istream& in) override;
    void ingestStream(std::istream& in) override;
    void ingestBytes(const uint8_t* bytes, int off, int sz) override;
    void endIngest() override;
    void clear() override;
    bool isEmpty() const override;

    std::string toString() const;
    std::vector<uint8_t> getBytes() const;

private:
    std::vector<uint8_t> buffer_;
    std::string description_;
    int maxBytes_ = 0;
    bool open_ = false;
};

} // namespace ghidra
