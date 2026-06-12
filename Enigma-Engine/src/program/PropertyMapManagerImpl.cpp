/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PropertyMapManagerImpl.cpp
/// \brief Implementation of property map manager
/// Translated from: ghidra.program.database.properties.DBPropertyMapManager

#include <ghidra/PropertyMapManagerImpl.h>
#include <algorithm>

namespace ghidra {

// AddressSetPropertyMapImpl

AddressSetPropertyMapImpl::AddressSetPropertyMapImpl(const std::string& name) : name_(name) {}

void AddressSetPropertyMapImpl::add(const Address& start, const Address& end) {
    set_.add(start, end);
}

void AddressSetPropertyMapImpl::add(const AddressSetView& addressSet) {
    set_.add(addressSet);
}

void AddressSetPropertyMapImpl::set(const AddressSetView& addressSet) {
    set_.clear();
    set_.add(addressSet);
}

void AddressSetPropertyMapImpl::remove(const Address& start, const Address& end) {
    set_.remove(start, end);
}

void AddressSetPropertyMapImpl::remove(const AddressSetView& addressSet) {
    set_.remove(addressSet);
}

AddressSet AddressSetPropertyMapImpl::getAddressSet() {
    return AddressSet(set_);
}

AddressIterator* AddressSetPropertyMapImpl::getAddresses() {
    std::vector<Address> addrs;
    auto* iter = set_.getAddressRanges(true);
    while (iter->hasNext()) {
        const AddressRange& range = iter->next();
        Address addr = range.getMinAddress();
        while (addr <= range.getMaxAddress()) {
            addrs.push_back(addr);
            addr = addr.add(1);
        }
    }
    delete iter;
    return new AddressIterator(addrs);
}

AddressRangeIterator* AddressSetPropertyMapImpl::getAddressRanges() {
    return set_.getAddressRanges();
}

void AddressSetPropertyMapImpl::clear() {
    set_.clear();
}

bool AddressSetPropertyMapImpl::contains(const Address& addr) {
    return set_.contains(addr);
}

// IntRangeMapImpl

int64_t IntRangeMapImpl::getValue(Address addr) {
    for (const auto& range : ranges_) {
        if (addr >= range.start && addr <= range.end) return range.value;
    }
    return 0;
}

void IntRangeMapImpl::setValue(Address start, Address end, int64_t value) {
    ranges_.push_back({start, end, value});
}

void IntRangeMapImpl::clearValue(Address start, Address end) {
    ranges_.erase(std::remove_if(ranges_.begin(), ranges_.end(),
        [&](const Range& r) { return r.start >= start && r.end <= end; }), ranges_.end());
}

// PropertyMapManagerImpl

AddressSetPropertyMap* PropertyMapManagerImpl::createAddressSetPropertyMap(const std::string& name) {
    auto map = std::make_unique<AddressSetPropertyMapImpl>(name);
    AddressSetPropertyMap* raw = map.get();
    addrSetMaps_[name] = std::move(map);
    return raw;
}

IntRangeMap* PropertyMapManagerImpl::createIntRangeMap(const std::string& name) {
    auto map = std::make_unique<IntRangeMapImpl>(name);
    IntRangeMap* raw = map.get();
    intRangeMaps_[name] = std::move(map);
    return raw;
}

AddressSetPropertyMap* PropertyMapManagerImpl::getAddressSetPropertyMap(const std::string& name) {
    auto it = addrSetMaps_.find(name);
    return (it != addrSetMaps_.end()) ? it->second.get() : nullptr;
}

IntRangeMap* PropertyMapManagerImpl::getIntRangeMap(const std::string& name) {
    auto it = intRangeMaps_.find(name);
    return (it != intRangeMaps_.end()) ? it->second.get() : nullptr;
}

void PropertyMapManagerImpl::deleteAddressSetPropertyMap(const std::string& name) {
    addrSetMaps_.erase(name);
}

void PropertyMapManagerImpl::deleteIntRangeMap(const std::string& name) {
    intRangeMaps_.erase(name);
}

} // namespace ghidra
