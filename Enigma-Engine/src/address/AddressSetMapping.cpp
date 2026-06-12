/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/AddressSetMapping.h"
#include <algorithm>
#include <stdexcept>

namespace ghidra {

AddressSetMapping::AddressSetMapping(const AddressSetView& set) : set_(&set) {
    if (set.getNumAddresses() > INT64_MAX) {
        throw std::invalid_argument("AddressSet too large for AddressSetMapping");
    }
    buildRanges();
    buildIndexes();
}

void AddressSetMapping::buildRanges() {
    auto* iter = set_->getAddressRanges(true);
    while (iter->hasNext()) {
        ranges_.push_back(iter->next());
    }
    delete iter;
}

void AddressSetMapping::buildIndexes() {
    indexes_.resize(ranges_.size() + 1);
    indexes_[0] = 0;
    for (size_t i = 0; i < ranges_.size(); ++i) {
        indexes_[i + 1] = indexes_[i] + ranges_[i].getLength();
    }
}

Address AddressSetMapping::getAddress(int index) const {
    if (index < 0 || index >= indexes_.back()) {
        return Address();
    }

    auto it = std::upper_bound(indexes_.begin(), indexes_.end(), static_cast<int64_t>(index)) - 1;
    size_t rangeIdx = static_cast<size_t>(it - indexes_.begin());
    if (rangeIdx >= ranges_.size()) {
        return Address();
    }

    int64_t offset = static_cast<int64_t>(index) - *it;
    return ranges_[rangeIdx].getMinAddress().add(offset);
}

} // namespace ghidra
