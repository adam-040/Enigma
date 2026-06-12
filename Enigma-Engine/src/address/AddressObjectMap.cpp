/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/AddressObjectMap.h"

namespace ghidra {

AddressObjectMap::AddressObjectMap() : addrMap_() {}

std::vector<void*> AddressObjectMap::getObjects(const Address& addr) const {
    int64_t key = const_cast<AddressMapImpl&>(addrMap_).getKey(addr);
    auto it = markers_.find(key);
    if (it != markers_.end()) {
        return it->second;
    }
    return {};
}

void AddressObjectMap::addObject(void* obj, const AddressSetView& set) {
    auto* iter = set.getAddressRanges();
    while (iter->hasNext()) {
        const AddressRange& range = iter->next();
        addObject(obj, range.getMinAddress(), range.getMaxAddress());
    }
    delete iter;
}

void AddressObjectMap::addObject(void* obj, const Address& startAddr, const Address& endAddr) {
    int64_t start = addrMap_.getKey(startAddr);
    int64_t end = addrMap_.getKey(endAddr);
    for (int64_t key = start; key <= end; ++key) {
        auto& vec = markers_[key];
        if (std::find(vec.begin(), vec.end(), obj) == vec.end()) {
            vec.push_back(obj);
        }
    }
}

void AddressObjectMap::removeObject(void* obj, const AddressSetView& set) {
    auto* iter = set.getAddressRanges();
    while (iter->hasNext()) {
        const AddressRange& range = iter->next();
        removeObject(obj, range.getMinAddress(), range.getMaxAddress());
    }
    delete iter;
}

void AddressObjectMap::removeObject(void* obj, const Address& startAddr, const Address& endAddr) {
    int64_t start = addrMap_.getKey(startAddr);
    int64_t end = addrMap_.getKey(endAddr);
    for (int64_t key = start; key <= end; ++key) {
        auto it = markers_.find(key);
        if (it != markers_.end()) {
            auto& vec = it->second;
            vec.erase(std::remove(vec.begin(), vec.end(), obj), vec.end());
            if (vec.empty()) {
                markers_.erase(it);
            }
        }
    }
}

} // namespace ghidra
