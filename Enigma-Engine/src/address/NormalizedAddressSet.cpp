/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/NormalizedAddressSet.h>
#include <ghidra/AddressRangeImpl.h>
#include <ghidra/AddressRangeIterator.h>
#include <algorithm>
#include <stdexcept>

namespace ghidra {

NormalizedAddressSet::NormalizedAddressSet() : addrMap_(nullptr) {}

NormalizedAddressSet::NormalizedAddressSet(AddressMap* addrMap)
    : addrMap_(dynamic_cast<AddressMapImpl*>(addrMap)) {
    if (addrMap && !addrMap_) {
        throw std::invalid_argument("AddressMap must be AddressMapImpl");
    }
}

void NormalizedAddressSet::add(const Address& addr) {
    addRange(addr, addr);
}

void NormalizedAddressSet::add(const AddressSetView& set) {
    auto* it = set.getAddressRanges();
    if (it) {
        while (it->hasNext()) {
            add(it->next());
        }
        delete it;
    }
}

void NormalizedAddressSet::add(const AddressRange& range) {
    addRange(range.getMinAddress(), range.getMaxAddress());
}

void NormalizedAddressSet::addRange(const Address& startAddr, const Address& endAddr) {
    if (!addrMap_) {
        throw std::runtime_error("NormalizedAddressSet has no AddressMap");
    }
    uint64_t start = addrMap_->getKey(startAddr);
    uint64_t end = addrMap_->getKey(endAddr);
    if ((start & AddressMapImpl::BASE_MASK) == (end & AddressMapImpl::BASE_MASK) && start <= end) {
        addKeyRange(start, end);
        return;
    }

    std::vector<KeyRange> ranges = addrMap_->getKeyRanges(startAddr, endAddr);
    for (const auto& kr : ranges) {
        addKeyRange(kr.minKey, kr.maxKey);
    }
}

void NormalizedAddressSet::clear() {
    baseLists_.clear();
    bases_.clear();
}

void NormalizedAddressSet::deleteSet(const AddressSetView& view) {
    if (!addrMap_) return;
    std::vector<KeyRange> list = addrMap_->getKeyRanges(&view);
    for (const auto& kr : list) {
        deleteKeyRange(kr.minKey, kr.maxKey);
    }
}

bool NormalizedAddressSet::contains(const Address& addr) const {
    if (!addrMap_ || !addr.isValid()) return false;
    uint64_t key = const_cast<AddressMapImpl*>(addrMap_)->getKey(addr);
    uint64_t baseKey = key & AddressMapImpl::BASE_MASK;
    auto it = baseLists_.find(baseKey);
    if (it != baseLists_.end()) {
        uint64_t offset = key & AddressMapImpl::ADDR_OFFSET_MASK;
        return it->second.contains(static_cast<int64_t>(offset));
    }
    return false;
}

bool NormalizedAddressSet::isEmpty() const {
    return baseLists_.empty();
}

int NormalizedAddressSet::getNumAddressRanges() const {
    int count = 0;
    for (const auto& pair : baseLists_) {
        count += pair.second.getNumRanges();
    }
    return count;
}

int64_t NormalizedAddressSet::getNumAddresses() const {
    int64_t count = 0;
    for (const auto& pair : baseLists_) {
        count += pair.second.getNumValues();
    }
    return count;
}

std::string NormalizedAddressSet::toString() const {
    auto ranges = getRanges();
    if (ranges.empty()) {
        return "[empty]\n";
    }
    std::string result;
    for (const auto& range : ranges) {
        result += range.toString();
        result += " ";
    }
    return result;
}

std::vector<AddressRange> NormalizedAddressSet::getRanges() const {
    std::vector<AddressRange> result;
    if (!addrMap_) return result;
    for (uint64_t base : bases_) {
        auto it = baseLists_.find(base);
        if (it != baseLists_.end()) {
            const SortedRangeList& srl = it->second;
            for (const auto& range : srl) {
                Address minAddr = const_cast<AddressMapImpl*>(addrMap_)->decodeAddress(base + range.min);
                Address maxAddr = const_cast<AddressMapImpl*>(addrMap_)->decodeAddress(base + range.max);
                result.emplace_back(minAddr, maxAddr);
            }
        }
    }
    return result;
}

void NormalizedAddressSet::addKeyRange(uint64_t minKey, uint64_t maxKey) {
    uint64_t baseKey = minKey & AddressMapImpl::BASE_MASK;
    auto it = baseLists_.find(baseKey);
    if (it == baseLists_.end()) {
        auto res = baseLists_.emplace(baseKey, SortedRangeList());
        bases_.push_back(baseKey);
        std::sort(bases_.begin(), bases_.end(), [this](uint64_t b1, uint64_t b2) {
            Address a1 = const_cast<AddressMapImpl*>(addrMap_)->decodeAddress(b1);
            Address a2 = const_cast<AddressMapImpl*>(addrMap_)->decodeAddress(b2);
            return a1 < a2;
        });
        it = res.first;
    }
    uint64_t minOffset = minKey & AddressMapImpl::ADDR_OFFSET_MASK;
    uint64_t maxOffset = maxKey & AddressMapImpl::ADDR_OFFSET_MASK;
    it->second.addRange(static_cast<int64_t>(minOffset), static_cast<int64_t>(maxOffset));
}

void NormalizedAddressSet::deleteKeyRange(uint64_t minKey, uint64_t maxKey) {
    uint64_t baseKey = minKey & AddressMapImpl::BASE_MASK;
    auto it = baseLists_.find(baseKey);
    if (it == baseLists_.end()) {
        return;
    }
    uint64_t minOffset = minKey & AddressMapImpl::ADDR_OFFSET_MASK;
    uint64_t maxOffset = maxKey & AddressMapImpl::ADDR_OFFSET_MASK;
    it->second.removeRange(static_cast<int64_t>(minOffset), static_cast<int64_t>(maxOffset));
    if (it->second.isEmpty()) {
        baseLists_.erase(it);
        bases_.erase(std::remove(bases_.begin(), bases_.end(), baseKey), bases_.end());
    }
}

} // namespace ghidra
