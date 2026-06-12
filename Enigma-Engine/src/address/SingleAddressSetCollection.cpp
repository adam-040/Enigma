/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/SingleAddressSetCollection.h"

namespace ghidra {

SingleAddressSetCollection::SingleAddressSetCollection(const AddressSetView& set) : set_(set) {}

bool SingleAddressSetCollection::intersects(const AddressSetView& addrSet) {
    return set_.intersects(addrSet);
}

bool SingleAddressSetCollection::intersects(const Address& start, const Address& end) {
    return set_.intersects(start, end);
}

bool SingleAddressSetCollection::contains(const Address& address) {
    return set_.contains(address);
}

bool SingleAddressSetCollection::hasFewerRangesThan(int rangeThreshold) {
    return set_.getNumAddressRanges() < rangeThreshold;
}

AddressSet SingleAddressSetCollection::getCombinedAddressSet() {
    return AddressSet(set_);
}

Address SingleAddressSetCollection::findFirstAddressInCommon(const AddressSetView& otherSet) {
    return set_.findFirstAddressInCommon(otherSet);
}

bool SingleAddressSetCollection::isEmpty() {
    return set_.isEmpty();
}

Address SingleAddressSetCollection::getMinAddress() {
    return set_.getMinAddress();
}

Address SingleAddressSetCollection::getMaxAddress() {
    return set_.getMaxAddress();
}

} // namespace ghidra
