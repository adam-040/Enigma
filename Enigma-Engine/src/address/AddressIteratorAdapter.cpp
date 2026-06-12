/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/AddressIteratorAdapter.h"

namespace ghidra {

AddressIteratorAdapter::AddressIteratorAdapter(const std::vector<Address>& addresses)
    : AddressIterator(addresses) {}

AddressIteratorAdapter::AddressIteratorAdapter(std::vector<Address>&& addresses)
    : AddressIterator(addresses) {
    addresses_ = std::move(addresses);
}

bool AddressIteratorAdapter::hasNext() const {
    return index_ < addresses_.size();
}

Address AddressIteratorAdapter::next() {
    if (!hasNext()) return Address();
    return addresses_[index_++];
}

Address AddressIteratorAdapter::current() const {
    if (index_ == 0 || index_ > addresses_.size()) return Address();
    return addresses_[index_ - 1];
}

void AddressIteratorAdapter::reset() {
    index_ = 0;
}

size_t AddressIteratorAdapter::remaining() const {
    return addresses_.size() - index_;
}

} // namespace ghidra
