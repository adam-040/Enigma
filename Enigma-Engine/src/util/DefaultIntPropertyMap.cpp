/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DefaultIntPropertyMap.cpp
/// \brief Default implementation of IntPropertyMap backed by std::map
/// Translated from: ghidra.program.model.util.DefaultIntPropertyMap
#include "ghidra/DefaultIntPropertyMap.h"
#include "ghidra/AddressIterator.h"
#include <algorithm>
#include <stdexcept>
#include <vector>

namespace ghidra {

DefaultIntPropertyMap::DefaultIntPropertyMap(const std::string& name) : name_(name) {}

std::string DefaultIntPropertyMap::getName() const { return name_; }

const std::type_info& DefaultIntPropertyMap::getValueClass() const {
    return typeid(int32_t);
}

void DefaultIntPropertyMap::clear() { map_.clear(); }

void DefaultIntPropertyMap::add(const Address& addr, int32_t value) {
    map_[addr.getOffset()] = value;
}

int32_t DefaultIntPropertyMap::getInt(const Address& addr) {
    auto it = map_.find(addr.getOffset());
    if (it == map_.end()) {
        throw NoValueException("No value at address");
    }
    return it->second;
}

bool DefaultIntPropertyMap::intersects(const Address& start, const Address& end) const {
    auto it = map_.lower_bound(start.getOffset());
    if (it == map_.end()) return false;
    return it->first <= end.getOffset();
}

bool DefaultIntPropertyMap::intersects(const AddressSetView& set) const {
    if (set.isEmpty()) return false;
    AddressSpace* space = set.getMinAddress().getAddressSpace();
    for (const auto& kv : map_) {
        Address a(space, kv.first);
        if (set.contains(a)) return true;
    }
    return false;
}

bool DefaultIntPropertyMap::removeRange(const Address& start, const Address& end) {
    auto lo = map_.lower_bound(start.getOffset());
    auto hi = map_.upper_bound(end.getOffset());
    bool removed = (lo != hi);
    map_.erase(lo, hi);
    return removed;
}

bool DefaultIntPropertyMap::remove(const Address& addr) {
    return map_.erase(addr.getOffset()) > 0;
}

bool DefaultIntPropertyMap::hasProperty(const Address& addr) const {
    return map_.find(addr.getOffset()) != map_.end();
}

Address DefaultIntPropertyMap::getNextPropertyAddress(const Address& addr) const {
    auto it = map_.upper_bound(addr.getOffset());
    if (it == map_.end()) {
        throw NoValueException("No next property address");
    }
    return Address(addr.getAddressSpace(), it->first);
}

Address DefaultIntPropertyMap::getPreviousPropertyAddress(const Address& addr) const {
    auto it = map_.lower_bound(addr.getOffset());
    if (it == map_.begin()) {
        throw NoValueException("No previous property address");
    }
    --it;
    return Address(addr.getAddressSpace(), it->first);
}

Address DefaultIntPropertyMap::getFirstPropertyAddress() const {
    if (map_.empty()) {
        throw NoValueException("No first property address");
    }
    return Address(nullptr, map_.begin()->first);
}

Address DefaultIntPropertyMap::getLastPropertyAddress() const {
    if (map_.empty()) {
        throw NoValueException("No last property address");
    }
    return Address(nullptr, map_.rbegin()->first);
}

int DefaultIntPropertyMap::getSize() const { return static_cast<int>(map_.size()); }

AddressIterator* DefaultIntPropertyMap::getPropertyIterator(const Address& start, const Address& end) const {
    return getPropertyIterator(start, end, true);
}

AddressIterator* DefaultIntPropertyMap::getPropertyIterator(const Address& start, const Address& end, bool forward) const {
    std::vector<Address> addrs;
    auto lo = map_.lower_bound(start.getOffset());
    auto hi = map_.upper_bound(end.getOffset());
    for (auto it = lo; it != hi; ++it) {
        addrs.emplace_back(start.getAddressSpace(), it->first);
    }
    if (!forward) {
        std::reverse(addrs.begin(), addrs.end());
    }
    return new AddressIterator(addrs);
}

AddressIterator* DefaultIntPropertyMap::getPropertyIterator() const {
    std::vector<Address> addrs;
    addrs.reserve(map_.size());
    for (const auto& kv : map_) {
        addrs.emplace_back(nullptr, kv.first);
    }
    return new AddressIterator(addrs);
}

AddressIterator* DefaultIntPropertyMap::getPropertyIterator(const AddressSetView& asv) const {
    return getPropertyIterator(asv, true);
}

AddressIterator* DefaultIntPropertyMap::getPropertyIterator(const AddressSetView& asv, bool forward) const {
    std::vector<Address> addrs;
    if (!asv.isEmpty()) {
        AddressSpace* space = asv.getMinAddress().getAddressSpace();
        for (const auto& kv : map_) {
            Address addr(space, kv.first);
            if (asv.contains(addr)) {
                addrs.push_back(addr);
            }
        }
    }
    if (!forward) {
        std::reverse(addrs.begin(), addrs.end());
    }
    return new AddressIterator(addrs);
}

AddressIterator* DefaultIntPropertyMap::getPropertyIterator(const Address& start, bool forward) const {
    std::vector<Address> addrs;
    if (forward) {
        for (auto it = map_.lower_bound(start.getOffset()); it != map_.end(); ++it) {
            addrs.emplace_back(start.getAddressSpace(), it->first);
        }
    }
    else {
        auto it = map_.upper_bound(start.getOffset());
        while (it != map_.begin()) {
            --it;
            addrs.emplace_back(start.getAddressSpace(), it->first);
        }
    }
    return new AddressIterator(addrs);
}

void DefaultIntPropertyMap::moveRange(const Address& start, const Address& end, const Address& newStart) {
    if (end.getOffset() < start.getOffset()) return;

    std::vector<std::pair<uint64_t, int32_t>> moved;
    auto lo = map_.lower_bound(start.getOffset());
    auto hi = map_.upper_bound(end.getOffset());
    for (auto it = lo; it != hi; ++it) {
        moved.emplace_back(static_cast<uint64_t>(it->first - start.getOffset()), it->second);
    }
    map_.erase(lo, hi);

    for (const auto& item : moved) {
        map_[newStart.getOffset() + static_cast<int64_t>(item.first)] = item.second;
    }
}

} // namespace ghidra
