/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AbstractAddressSetView.cpp
/// \brief Abstract base for address set views
/// Translated from: ghidra.program.model.address.AbstractAddressSetView

#include <ghidra/AbstractAddressSetView.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AddressRangeVectorIterator.h>
#include <algorithm>

namespace ghidra {

bool AbstractAddressSetView::isEmpty() const {
    return getRanges().empty();
}

bool AbstractAddressSetView::contains(const Address& start, const Address& end) const {
    if (isEmpty()) return false;
    AddressRange range = getRangeContaining(start);
    return range.getLength() > 0 && range.contains(end);
}

bool AbstractAddressSetView::contains(const AddressSetView& rangeSet) const {
    if (rangeSet.isEmpty()) return true;
    if (isEmpty()) return false;
    auto it = rangeSet.getAddressRanges();
    while (it->hasNext()) {
        const AddressRange& range = it->next();
        if (!contains(range.getMinAddress(), range.getMaxAddress())) {
            delete it;
            return false;
        }
    }
    delete it;
    return true;
}

Address AbstractAddressSetView::getMinAddress() const {
    auto ranges = getRanges();
    if (ranges.empty()) return Address();
    return ranges.front().getMinAddress();
}

Address AbstractAddressSetView::getMaxAddress() const {
    auto ranges = getRanges();
    if (ranges.empty()) return Address();
    return ranges.back().getMaxAddress();
}

int AbstractAddressSetView::getNumAddressRanges() const {
    return static_cast<int>(getRanges().size());
}

AddressRangeIterator* AbstractAddressSetView::getAddressRanges() const {
    return getAddressRanges(true);
}

AddressRangeIterator* AbstractAddressSetView::getAddressRanges(bool forward) const {
    return getAddressRanges(forward ? getMinAddress() : getMaxAddress(), forward);
}

AddressRangeIterator* AbstractAddressSetView::getAddressRanges(const Address& start, bool forward) const {
    return new AddressRangeVectorIterator(getRanges(), start, forward);
}

int64_t AbstractAddressSetView::getNumAddresses() const {
    int64_t count = 0;
    auto it = getAddressRanges();
    while (it->hasNext()) {
        const AddressRange& range = it->next();
        count += range.getLength();
    }
    delete it;
    return count;
}

bool AbstractAddressSetView::hasSameAddresses(const AddressSetView& view) const {
    if (getNumAddressRanges() != view.getNumAddressRanges()) return false;
    auto thisIt = getAddressRanges();
    auto otherIt = view.getAddressRanges();
    bool same = true;
    while (thisIt->hasNext() && otherIt->hasNext()) {
        if (!(thisIt->next() == otherIt->next())) { same = false; break; }
    }
    delete thisIt;
    delete otherIt;
    return same;
}

AddressRange AbstractAddressSetView::getFirstRange() const {
    auto ranges = getRanges();
    if (ranges.empty()) return AddressRange();
    return ranges.front();
}

AddressRange AbstractAddressSetView::getLastRange() const {
    auto ranges = getRanges();
    if (ranges.empty()) return AddressRange();
    return ranges.back();
}

bool AbstractAddressSetView::intersects(const AddressSetView& addrSet) const {
    auto it = getAddressRanges();
    while (it->hasNext()) {
        const AddressRange& range = it->next();
        if (addrSet.intersects(range.getMinAddress(), range.getMaxAddress())) {
            delete it;
            return true;
        }
    }
    delete it;
    return false;
}

bool AbstractAddressSetView::intersects(const Address& start, const Address& end) const {
    auto it = getAddressRanges();
    while (it->hasNext()) {
        const AddressRange& range = it->next();
        if (range.intersects(start, end)) { delete it; return true; }
    }
    delete it;
    return false;
}

AddressSet AbstractAddressSetView::intersect(const AddressSetView& view) const {
    AddressSet result;
    auto thisIt = getAddressRanges();
    while (thisIt->hasNext()) {
        const AddressRange& thisRange = thisIt->next();
        auto otherIt = view.getAddressRanges();
        while (otherIt->hasNext()) {
            const AddressRange& otherRange = otherIt->next();
            if (thisRange.intersects(otherRange)) {
                AddressRange* intersection = thisRange.intersect(otherRange);
                if (intersection) {
                    result.add(*intersection);
                    delete intersection;
                }
            }
        }
        delete otherIt;
    }
    delete thisIt;
    return result;
}

AddressSet AbstractAddressSetView::intersectRange(const Address& start, const Address& end) const {
    AddressSet result;
    AddressRange queryRange(start, end);
    auto it = getAddressRanges();
    while (it->hasNext()) {
        const AddressRange& range = it->next();
        if (range.intersects(queryRange)) {
            AddressRange* intersection = range.intersect(queryRange);
            if (intersection) {
                result.add(*intersection);
                delete intersection;
            }
        }
    }
    delete it;
    return result;
}

AddressSet AbstractAddressSetView::unionSet(const AddressSetView& addrSet) const {
    AddressSet result;
    auto it = getAddressRanges();
    while (it->hasNext()) { result.add(it->next()); }
    delete it;
    auto otherIt = addrSet.getAddressRanges();
    while (otherIt->hasNext()) { result.add(otherIt->next()); }
    delete otherIt;
    return result;
}

AddressSet AbstractAddressSetView::subtract(const AddressSetView& addrSet) const {
    AddressSet result;
    auto it = getAddressRanges();
    while (it->hasNext()) {
        const AddressRange& range = it->next();
        AddressSet tmp;
        tmp.add(range);
        auto subIt = addrSet.getAddressRanges();
        while (subIt->hasNext()) {
            const AddressRange& subRange = subIt->next();
            if (tmp.intersects(subRange.getMinAddress(), subRange.getMaxAddress())) {
                tmp = tmp.subtract(AddressSet(subRange));
            }
        }
        delete subIt;
        result = result.unionSet(tmp);
    }
    delete it;
    return result;
}

AddressSet AbstractAddressSetView::xorSet(const AddressSetView& addrSet) const {
    AddressSet aMinusB = subtract(addrSet);
    AddressSet bMinusA;
    auto it = addrSet.getAddressRanges();
    while (it->hasNext()) {
        AddressSet tmp;
        tmp.add(it->next());
        bMinusA = bMinusA.unionSet(tmp.subtract(*this));
    }
    delete it;
    return aMinusB.unionSet(bMinusA);
}

Address AbstractAddressSetView::findFirstAddressInCommon(const AddressSetView& set) const {
    auto thisIt = getAddressRanges();
    while (thisIt->hasNext()) {
        const AddressRange& range = thisIt->next();
        if (set.intersects(range.getMinAddress(), range.getMaxAddress())) {
            auto otherIt = set.getAddressRanges();
            while (otherIt->hasNext()) {
                const AddressRange& otherRange = otherIt->next();
                if (range.intersects(otherRange)) {
                    Address iMin = (range.getMinAddress() > otherRange.getMinAddress())
                        ? range.getMinAddress() : otherRange.getMinAddress();
                    delete thisIt;
                    delete otherIt;
                    return iMin;
                }
            }
            delete otherIt;
        }
    }
    delete thisIt;
    return Address();
}

AddressRange AbstractAddressSetView::getRangeContaining(const Address& address) const {
    auto it = getAddressRanges();
    while (it->hasNext()) {
        const AddressRange& range = it->next();
        if (range.contains(address)) { delete it; return range; }
    }
    delete it;
    return AddressRange();
}

} // namespace ghidra
