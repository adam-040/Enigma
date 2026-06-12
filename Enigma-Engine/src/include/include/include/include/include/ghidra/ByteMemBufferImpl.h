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
/// \file ByteMemBufferImpl.h
/// \brief Simple byte buffer implementation of MemBuffer
/// Translated from: ghidra.program.model.mem.ByteMemBufferImpl
#pragma once

#include <cstdint>
#include <vector>
#include <memory>
#include <istream>
#include <sstream>
#include "ghidra/MemBuffer.h"
#include "ghidra/GhidraDataConverter.h"

namespace ghidra {

/**
 * Simple byte buffer implementation of the MemBuffer.
 * Even if a Memory is provided, the available bytes will be limited
 * to the bytes provided during construction.
 */
class ByteMemBufferImpl : public MemBuffer {
private:
    const GhidraDataConverter* converter_;
    std::vector<uint8_t> bytes_;
    Address addr_;
    Memory* mem_;

public:
    /// Construct with address, bytes, and endianness
    ByteMemBufferImpl(const Address& addr, const std::vector<uint8_t>& bytes, bool isBigEndian);

    /// Construct with memory, address, bytes, and endianness
    ByteMemBufferImpl(Memory* memory, const Address& addr, const std::vector<uint8_t>& bytes, bool isBigEndian);

    /// Construct with raw byte array
    ByteMemBufferImpl(const Address& addr, const uint8_t* bytes, int length, bool isBigEndian);

    /// Get number of bytes contained within buffer
    int getLength() const;

    Address getAddress() const override;

    Memory* getMemory() const override;

    int8_t getByte(int offset) const override;

    int getBytes(std::vector<uint8_t>& b, int offset) const override;

    int getBytes(uint8_t* b, int length, int offset) const override;

    bool isBigEndian() const override;

    int16_t getShort(int offset) const override;

    int32_t getInt(int offset) const override;

    int64_t getLong(int offset) const override;

    std::vector<uint8_t> getBigInteger(int offset, int size, bool signed_val) const override;

    std::unique_ptr<std::istream> getInputStream() const override;

    std::unique_ptr<std::istream> getInputStream(int initialPosition, int length) const override;
};

} // namespace ghidra
