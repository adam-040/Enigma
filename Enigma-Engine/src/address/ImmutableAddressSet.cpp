/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/ImmutableAddressSet.h"

namespace ghidra {

const ImmutableAddressSet& ImmutableAddressSet::EMPTY_SET() {
    static ImmutableAddressSet instance{AddressSet()};
    return instance;
}

ImmutableAddressSet ImmutableAddressSet::asImmutable(const AddressSetView* view) {
    if (view == nullptr) {
        return ImmutableAddressSet(static_cast<const AddressSetView&>(EMPTY_SET()));
    }
    auto* ias = dynamic_cast<const ImmutableAddressSet*>(view);
    if (ias != nullptr) {
        return *ias;
    }
    return ImmutableAddressSet(*view);
}

ImmutableAddressSet::ImmutableAddressSet(const AddressSetView& addresses) : set_(addresses) {}

ImmutableAddressSet::ImmutableAddressSet(const AddressSet& addresses) : set_(addresses) {}

bool ImmutableAddressSet::contains(const Address& addr) const { return set_.contains(addr); }

bool ImmutableAddressSet::contains(const Address& start, const Address& end) const {
    return set_.contains(start, end);
}

bool ImmutableAddressSet::contains(const AddressSetView& rangeSet) const {
    return set_.contains(rangeSet);
}

bool ImmutableAddressSet::isEmpty() const { return set_.isEmpty(); }

Address ImmutableAddressSet::getMinAddress() const { return set_.getMinAddress(); }

Address ImmutableAddressSet::getMaxAddress() const { return set_.getMaxAddress(); }

int ImmutableAddressSet::getNumAddressRanges() const { return set_.getNumAddressRanges(); }

int64_t ImmutableAddressSet::getNumAddresses() const { return set_.getNumAddresses(); }

AddressRangeIterator* ImmutableAddressSet::getAddressRanges() const {
    return set_.getAddressRanges();
}

AddressRangeIterator* ImmutableAddressSet::getAddressRanges(bool forward) const {
    return set_.getAddressRanges(forward);
}

AddressRangeIterator* ImmutableAddressSet::getAddressRanges(const Address& start, bool forward) const {
    return set_.getAddressRanges(start, forward);
}

bool ImmutableAddressSet::intersects(const AddressSetView& other) const {
    return set_.intersects(other);
}

bool ImmutableAddressSet::intersects(const Address& start, const Address& end) const {
    return set_.intersects(start, end);
}

AddressSet ImmutableAddressSet::intersect(const AddressSetView& view) const {
    return set_.intersect(view);
}

AddressSet ImmutableAddressSet::intersectRange(const Address& start, const Address& end) const {
    return set_.intersectRange(start, end);
}

AddressSet ImmutableAddressSet::unionSet(const AddressSetView& addrSet) const {
    return set_.unionSet(addrSet);
}

AddressSet ImmutableAddressSet::subtract(const AddressSetView& addrSet) const {
    return set_.subtract(addrSet);
}

AddressSet ImmutableAddressSet::xorSet(const AddressSetView& addrSet) const {
    return set_.xorSet(addrSet);
}

bool ImmutableAddressSet::hasSameAddresses(const AddressSetView& other) const {
    return set_.hasSameAddresses(other);
}

AddressRange ImmutableAddressSet::getFirstRange() const { return set_.getFirstRange(); }

AddressRange ImmutableAddressSet::getLastRange() const { return set_.getLastRange(); }

AddressRange ImmutableAddressSet::getRangeContaining(const Address& address) const {
    return set_.getRangeContaining(address);
}

Address ImmutableAddressSet::findFirstAddressInCommon(const AddressSetView& set) const {
    return set_.findFirstAddressInCommon(set);
}

bool ImmutableAddressSet::equals(const ImmutableAddressSet& other) const {
    if (getNumAddresses() != other.getNumAddresses()) return false;
    if (getNumAddressRanges() != other.getNumAddressRanges()) return false;

    auto* myRanges = getAddressRanges(true);
    auto* otherRanges = other.getAddressRanges(true);
    while (myRanges->hasNext() && otherRanges->hasNext()) {
        if (!myRanges->next().equals(otherRanges->next())) {
            delete myRanges;
            delete otherRanges;
            return false;
        }
    }
    bool result = !myRanges->hasNext() && !otherRanges->hasNext();
    delete myRanges;
    delete otherRanges;
    return result;
}

int ImmutableAddressSet::hashCode() const {
    if (isEmpty()) return 0;
    return static_cast<int>(getMinAddress().hash() + getMaxAddress().hash());
}

} // namespace ghidra
