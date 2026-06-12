/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file MemBufferImageInputStream.h
/// \brief Wraps a MemBuffer as a byte input stream for image reading
/// Translated from: ghidra.program.model.data.MemBufferImageInputStream
#pragma once

#include <ghidra/MemBuffer.h>
#include <cstdint>

namespace ghidra {

class MemBufferImageInputStream {
private:
    MemBuffer* buf_;
    int64_t streamPos_ = 0;

public:
    explicit MemBufferImageInputStream(MemBuffer* buf);

    int read();
    int read(uint8_t* b, int off, int len);
    int64_t getConsumedLength() const { return streamPos_; }
};

} // namespace ghidra
