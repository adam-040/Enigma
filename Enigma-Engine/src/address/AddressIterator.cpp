/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AddressIterator.cpp
/// \brief Iterator for addresses implementation
#include "ghidra/AddressIterator.h"

namespace ghidra {

AddressIterator::AddressIterator() : index_(0) {}

AddressIterator::AddressIterator(const std::vector<Address>& addresses)
    : addresses_(addresses), index_(0) {}

bool AddressIterator::hasNext() const {
    return index_ < addresses_.size();
}

Address AddressIterator::next() {
    if (!hasNext()) return Address();
    return addresses_[index_++];
}

Address AddressIterator::current() const {
    if (index_ == 0 || index_ > addresses_.size()) return Address();
    return addresses_[index_ - 1];
}

void AddressIterator::reset() {
    index_ = 0;
}

size_t AddressIterator::remaining() const {
    return addresses_.size() - index_;
}

} // namespace ghidra
