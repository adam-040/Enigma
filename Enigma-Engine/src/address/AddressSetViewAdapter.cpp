/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/AddressSetViewAdapter.h"

namespace ghidra {

AddressSetViewAdapter::AddressSetViewAdapter(const AddressSetView& set)
    : set_(new AddressSet(set)) {}

AddressSetViewAdapter::AddressSetViewAdapter()
    : set_(new AddressSet()) {}

bool AddressSetViewAdapter::contains(const Address& addr) const {
    return set_->contains(addr);
}

bool AddressSetViewAdapter::contains(const Address& start, const Address& end) const {
    return set_->contains(start, end);
}

bool AddressSetViewAdapter::contains(const AddressSetView& rangeSet) const {
    return set_->contains(rangeSet);
}

bool AddressSetViewAdapter::isEmpty() const { return set_->isEmpty(); }

Address AddressSetViewAdapter::getMinAddress() const { return set_->getMinAddress(); }

Address AddressSetViewAdapter::getMaxAddress() const { return set_->getMaxAddress(); }

int AddressSetViewAdapter::getNumAddressRanges() const { return set_->getNumAddressRanges(); }

int64_t AddressSetViewAdapter::getNumAddresses() const { return set_->getNumAddresses(); }

AddressRangeIterator* AddressSetViewAdapter::getAddressRanges() const {
    return set_->getAddressRanges();
}

AddressRangeIterator* AddressSetViewAdapter::getAddressRanges(bool forward) const {
    return set_->getAddressRanges(forward);
}

AddressRangeIterator* AddressSetViewAdapter::getAddressRanges(const Address& start, bool forward) const {
    return set_->getAddressRanges(start, forward);
}

bool AddressSetViewAdapter::intersects(const AddressSetView& other) const {
    return set_->intersects(other);
}

bool AddressSetViewAdapter::intersects(const Address& start, const Address& end) const {
    return set_->intersects(start, end);
}

AddressSet AddressSetViewAdapter::intersect(const AddressSetView& view) const {
    return set_->intersect(view);
}

AddressSet AddressSetViewAdapter::intersectRange(const Address& start, const Address& end) const {
    return set_->intersectRange(start, end);
}

AddressSet AddressSetViewAdapter::unionSet(const AddressSetView& addrSet) const {
    return set_->unionSet(addrSet);
}

AddressSet AddressSetViewAdapter::subtract(const AddressSetView& addrSet) const {
    return set_->subtract(addrSet);
}

AddressSet AddressSetViewAdapter::xorSet(const AddressSetView& addrSet) const {
    return set_->xorSet(addrSet);
}

bool AddressSetViewAdapter::hasSameAddresses(const AddressSetView& other) const {
    return set_->hasSameAddresses(other);
}

AddressRange AddressSetViewAdapter::getFirstRange() const { return set_->getFirstRange(); }

AddressRange AddressSetViewAdapter::getLastRange() const { return set_->getLastRange(); }

AddressRange AddressSetViewAdapter::getRangeContaining(const Address& address) const {
    return set_->getRangeContaining(address);
}

Address AddressSetViewAdapter::findFirstAddressInCommon(const AddressSetView& set) const {
    return set_->findFirstAddressInCommon(set);
}

bool AddressSetViewAdapter::equals(const AddressSetViewAdapter& other) const {
    return set_->hasSameAddresses(*other.set_);
}

int AddressSetViewAdapter::hashCode() const {
    return set_->isEmpty() ? 0 : static_cast<int>(set_->getMinAddress().hash() + set_->getMaxAddress().hash());
}

std::string AddressSetViewAdapter::toString() const {
    return "AddressSetViewAdapter";
}

} // namespace ghidra
