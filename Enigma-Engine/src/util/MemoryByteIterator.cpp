/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file MemoryByteIterator.cpp
/// \brief Iterator over bytes in memory for an address set
/// Translated from: ghidra.program.model.util.MemoryByteIterator
#include "ghidra/MemoryByteIterator.h"
#include "ghidra/Memory.h"
#include "ghidra/AddressSet.h"
#include "ghidra/AddressSetView.h"
#include "ghidra/AddressRange.h"
#include "ghidra/Address.h"
#include <stdexcept>

namespace ghidra {

MemoryByteIterator::MemoryByteIterator(Memory* mem, const AddressSetView& set)
    : mem_(mem), bufSize_(0), pos_(0), ownsAddrSet_(true) {
    addrSet_ = new AddressSet(set);
    int64_t totalSize = addrSet_->getNumAddresses();
    int bufLen = (totalSize < (int64_t)MAX_BUF_SIZE) ? (int)totalSize : MAX_BUF_SIZE;
    if (bufLen <= 0) bufLen = 1;
    buf_.resize(bufLen);
}

MemoryByteIterator::~MemoryByteIterator() {
    if (ownsAddrSet_) delete addrSet_;
}

bool MemoryByteIterator::hasNext() {
    while (pos_ >= bufSize_) {
        if (addrSet_->isEmpty()) return false;
        AddressRange firstRange = addrSet_->getFirstRange();
        Address addr = firstRange.getMinAddress();
        int64_t rangeLen = firstRange.getLength();
        int readSize = (int)((rangeLen < (int64_t)buf_.size()) ? rangeLen : (int64_t)buf_.size());
        if (readSize <= 0) {
            addrSet_->remove(firstRange.getMinAddress(), firstRange.getMaxAddress());
            continue;
        }
        Address endAddr(addr.getAddressSpace(), addr.getOffset() + (readSize - 1));
        addrSet_->remove(firstRange.getMinAddress(), endAddr);
        pos_ = 0;
        bufSize_ = mem_->getBytes(addr, buf_.data(), readSize);
        if (bufSize_ <= 0) {
            bufSize_ = 0;
        }
    }
    return pos_ < bufSize_;
}

uint8_t MemoryByteIterator::nextByte() {
    if (!hasNext()) {
        throw std::out_of_range("MemoryByteIterator: no more elements");
    }
    return buf_[pos_++];
}

int8_t MemoryByteIterator::next() {
    return (int8_t)nextByte();
}

} // namespace ghidra
