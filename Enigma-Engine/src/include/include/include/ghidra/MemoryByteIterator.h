/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file MemoryByteIterator.h
/// \brief Iterator over bytes in memory for an address set
/// Translated from: ghidra.program.model.util.MemoryByteIterator
#pragma once

#include <cstdint>
#include <vector>

namespace ghidra {

class Memory;
class AddressSet;
class AddressSetView;

/// Translated from: ghidra.program.model.util.MemoryByteIterator
class MemoryByteIterator {
public:
    static constexpr int MAX_BUF_SIZE = 16 * 1024;

private:
    Memory* mem_;
    AddressSet* addrSet_;
    std::vector<uint8_t> buf_;
    int bufSize_;
    int pos_;
    bool ownsAddrSet_;

public:
    MemoryByteIterator(Memory* mem, const AddressSetView& set);
    ~MemoryByteIterator();

    bool hasNext();
    uint8_t nextByte();
    int8_t next();
};

} // namespace ghidra
