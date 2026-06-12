/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/AddressMapImpl.h>
#include <ghidra/OverlayAddressSpace.h>
#include <ghidra/DefaultAddressFactory.h>
#include <ghidra/ProgramAddressFactory.h>
#include <ghidra/Address.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/AddressSet.h>
#include <algorithm>
#include <stdexcept>
#include <iostream>

namespace ghidra {

namespace {

// Helper to get max offset from an AddressSpace safely
int64_t getMaxOffset(const AddressSpace* space) {
    if (!space) return 0;
    const auto* genSpace = dynamic_cast<const GenericAddressSpace*>(space);
    if (genSpace) {
        return genSpace->getMaxOffset();
    }
    int size = space->getSize();
    if (size == 64) return -1LL;
    return (1LL << size) - 1;
}

// Binary search helper for Address vector
int binarySearch(const std::vector<Address>& vec, const Address& addr) {
    auto it = std::lower_bound(vec.begin(), vec.end(), addr);
    if (it != vec.end() && *it == addr) {
        return static_cast<int>(std::distance(vec.begin(), it));
    }
    return -static_cast<int>(std::distance(vec.begin(), it)) - 1;
}

class OverlayAddressSpaceImpl : public OverlayAddressSpace {
private:
    AddressSet overlayAddressSet_;

public:
    OverlayAddressSpaceImpl(AddressSpace* baseSpace, int unique, const std::string& name)
        : OverlayAddressSpace(baseSpace, unique, name) {}

    bool contains(int64_t offset) const override {
        return overlayAddressSet_.isEmpty() || overlayAddressSet_.contains(Address(const_cast<OverlayAddressSpaceImpl*>(this), offset));
    }

    AddressSet getOverlayAddressSet() const override {
        return overlayAddressSet_;
    }

    void addRange(const Address& start, const Address& end) {
        overlayAddressSet_.addRange(start, end);
    }
};

class ObsoleteOverlaySpace : public OverlayAddressSpace {
private:
    OverlayAddressSpace* originalSpace_;
    std::string name_;

public:
    ObsoleteOverlaySpace(OverlayAddressSpace* ovSpace)
        : OverlayAddressSpace(ovSpace->getOverlayedSpace(), ovSpace->getUnique(), "DELETED_" + ovSpace->getName() + "_" + std::to_string(ovSpace->getSpaceID())),
          originalSpace_(ovSpace),
          name_("DELETED_" + ovSpace->getName() + "_" + std::to_string(ovSpace->getSpaceID())) {}

    OverlayAddressSpace* getOriginalSpace() const {
        return originalSpace_;
    }

    std::string getName() const override {
        return name_;
    }

    bool contains(int64_t offset) const override {
        return false;
    }

    AddressSet getOverlayAddressSet() const override {
        return AddressSet();
    }
};

} // namespace

AddressMapImpl::AddressMapImpl() : AddressMapImpl(0, nullptr) {}

AddressMapImpl::AddressMapImpl(uint8_t mapID, AddressFactory* addrFactory)
    : mapID_(mapID), addrFactory_(addrFactory) {
    mapIdBits_ = static_cast<uint64_t>(mapID) << (64 - MAP_ID_SIZE);
    init();
}

void AddressMapImpl::init() {
    lastBaseIndex_ = static_cast<int>(baseAddrs_.size()) - 1;
    sortedBaseStartAddrs_ = baseAddrs_;
    std::sort(sortedBaseStartAddrs_.begin(), sortedBaseStartAddrs_.end());

    sortedBaseEndAddrs_.resize(sortedBaseStartAddrs_.size());
    for (size_t i = 0; i < sortedBaseStartAddrs_.size(); ++i) {
        int64_t maxOffset = getMaxOffset(sortedBaseStartAddrs_[i].getAddressSpace());
        maxOffset = maxOffset < 0 ? static_cast<int64_t>(MAX_OFFSET) : std::min(maxOffset, static_cast<int64_t>(MAX_OFFSET));
        uint64_t off = sortedBaseStartAddrs_[i].getOffset() | maxOffset;
        sortedBaseEndAddrs_[i] = Address(sortedBaseStartAddrs_[i].getAddressSpace(), off);
    }

    addrToIndexMap_.clear();
    for (size_t i = 0; i < baseAddrs_.size(); ++i) {
        if (addrToIndexMap_.find(baseAddrs_[i]) == addrToIndexMap_.end()) {
            addrToIndexMap_[baseAddrs_[i]] = static_cast<int>(i);
        }
    }
}

int AddressMapImpl::getNumAddressSpaces() const {
    return addrFactory_ ? addrFactory_->getNumAddressSpaces() : 0;
}

AddressSpace* AddressMapImpl::getLanguageAddressSpace(int id) const {
    return addrFactory_ ? const_cast<AddressSpace*>(addrFactory_->getAddressSpace(id)) : nullptr;
}

int AddressMapImpl::getLanguageAddressSpaceID(const AddressSpace* space) const {
    return space ? space->getSpaceID() : NO_ADDRESS_SPACE_INDEX;
}

Address AddressMapImpl::mapLanguageAddress(const Address& langAddr) const {
    if (!langAddr.isValid()) return langAddr;
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    for (const auto& pair : overlaySpaces_) {
        const auto* ov = dynamic_cast<const OverlayAddressSpace*>(pair.second.get());
        if (ov && ov->getOverlayedSpace() == langAddr.getAddressSpace()) {
            if (ov->contains(langAddr.getOffset())) {
                return Address(const_cast<OverlayAddressSpace*>(ov), langAddr.getOffset());
            }
        }
    }
    return langAddr;
}

Address AddressMapImpl::mapInternalAddress(const Address& internalAddr) const {
    if (!internalAddr.isValid()) return internalAddr;
    const auto* ov = dynamic_cast<const OverlayAddressSpace*>(internalAddr.getAddressSpace());
    if (ov) {
        return const_cast<OverlayAddressSpace*>(ov)->translateAddress(internalAddr);
    }
    return internalAddr;
}

int AddressMapImpl::getOverlaySpaceCount() const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return static_cast<int>(overlaySpaces_.size());
}

AddressSpace* AddressMapImpl::getOverlaySpace(const std::string& name) const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto it = overlaySpaces_.find(name);
    if (it != overlaySpaces_.end()) {
        return it->second.get();
    }
    return nullptr;
}

AddressSpace* AddressMapImpl::createOverlaySpace(const std::string& name, AddressSpace* baseSpace) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    int unique = nextUniqueOverlay_++;
    auto ov = std::make_unique<OverlayAddressSpaceImpl>(baseSpace, unique, name);
    auto* ovPtr = ov.get();
    overlaySpaces_[name] = std::move(ov);

    if (addrFactory_) {
        auto* paf = dynamic_cast<ProgramAddressFactory*>(addrFactory_);
        if (paf) {
            paf->addAddressSpace(ovPtr);
        } else {
            auto* daf = dynamic_cast<DefaultAddressFactory*>(addrFactory_);
            if (daf) {
                daf->addAddressSpace(ovPtr);
            }
        }
    }

    spaceMap_[name] = ovPtr;
    return ovPtr;
}

bool AddressMapImpl::removeOverlaySpace(const std::string& name) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto it = overlaySpaces_.find(name);
    if (it == overlaySpaces_.end()) {
        return false;
    }

    auto* ovSpace = dynamic_cast<OverlayAddressSpace*>(it->second.get());
    if (ovSpace) {
        auto obsolete = std::make_unique<ObsoleteOverlaySpace>(ovSpace);
        auto* obsPtr = obsolete.get();
        std::string obsName = obsPtr->getName();

        if (addrFactory_) {
            auto* paf = dynamic_cast<ProgramAddressFactory*>(addrFactory_);
            if (paf) {
                paf->removeAddressSpace(name);
            } else {
                auto* daf = dynamic_cast<DefaultAddressFactory*>(addrFactory_);
                if (daf) {
                    daf->removeAddressSpace(name);
                }
            }
        }

        overlaySpaces_[obsName] = std::move(obsolete);
        spaceMap_[obsName] = obsPtr;
    }

    overlaySpaces_.erase(it);
    spaceMap_.erase(name);
    return true;
}

std::vector<std::string> AddressMapImpl::getOverlaySpaceNames() const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<std::string> names;
    for (const auto& pair : overlaySpaces_) {
        names.push_back(pair.first);
    }
    return names;
}

bool AddressMapImpl::hasOverlaySpaces() const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return !overlaySpaces_.empty();
}

AddressSpace* AddressMapImpl::getDefaultAddressSpace() const {
    return addrFactory_ ? const_cast<AddressSpace*>(addrFactory_->getDefaultAddressSpace()) : nullptr;
}

Address AddressMapImpl::decodeAddress(uint64_t value) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if ((value & MAP_ID_MASK) != mapIdBits_) {
        return Address::NO_ADDRESS;
    }

    int baseIndex = static_cast<int>(value >> ADDR_OFFSET_SIZE) & BASE_ID_MASK;
    uint64_t offset = value & ADDR_OFFSET_MASK;

    if (baseIndex == STACK_SPACE_ID && stackSpace_ != nullptr) {
        return Address(stackSpace_, static_cast<int64_t>(offset));
    }
    if (baseIndex >= static_cast<int>(baseAddrs_.size())) {
        return Address::NO_ADDRESS;
    }
    return baseAddrs_[baseIndex].addWrap(static_cast<int64_t>(offset));
}

uint64_t AddressMapImpl::getKey(const Address& addr) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return mapIdBits_ | (static_cast<uint64_t>(getBaseAddressIndex(addr)) << ADDR_OFFSET_SIZE) |
           (addr.getOffset() & ADDR_OFFSET_MASK);
}

int AddressMapImpl::getBaseAddressIndex(const Address& addr) {
    AddressSpace* space = addr.getAddressSpace();
    if (space->isStackSpace()) {
        if (stackSpace_ != nullptr && stackSpace_ != space) {
            throw std::invalid_argument("Only one stack space allowed");
        }
        stackSpace_ = space;
        return STACK_SPACE_ID;
    }

    uint64_t baseOffset = addr.getOffset() & BASE_MASK;

    if (lastBaseIndex_ >= 0) {
        const Address& base = baseAddrs_[lastBaseIndex_];
        if (base.hasSameAddressSpace(addr) && static_cast<uint64_t>(base.getOffset()) == baseOffset) {
            return lastBaseIndex_;
        }
    }

    int search = binarySearch(sortedBaseStartAddrs_, addr);
    if (search < 0) {
        search = -search - 2;
    }
    if (search >= 0) {
        const Address& base = sortedBaseStartAddrs_[search];
        if (base.hasSameAddressSpace(addr) && static_cast<uint64_t>(base.getOffset()) == baseOffset) {
            int index = addrToIndexMap_[base];
            lastBaseIndex_ = index;
            return index;
        }
    }

    checkAddressSpace(addr.getAddressSpace());
    int index = static_cast<int>(baseAddrs_.size());

    baseAddrs_.push_back(Address(addr.getAddressSpace(), static_cast<int64_t>(baseOffset)));
    init();
    lastBaseIndex_ = index;
    return lastBaseIndex_;
}

void AddressMapImpl::checkAddressSpace(AddressSpace* addrSpace) {
    std::string name = addrSpace->getName();
    auto it = spaceMap_.find(name);
    if (it == spaceMap_.end()) {
        spaceMap_[name] = addrSpace;
    } else if (it->second != addrSpace) {
        throw std::invalid_argument("Address space conflicts with another space in map");
    }
}

int AddressMapImpl::findKeyRange(const std::vector<KeyRange>& keyRangeList, const Address& addr) {
    if (!addr.isValid()) {
        return -1;
    }
    int low = 0;
    int high = static_cast<int>(keyRangeList.size()) - 1;
    while (low <= high) {
        int mid = low + (high - low) / 2;
        const auto& range = keyRangeList[mid];
        Address minAddr = decodeAddress(range.minKey);
        Address maxAddr = decodeAddress(range.maxKey);

        if (minAddr > addr) {
            high = mid - 1;
        } else if (maxAddr < addr) {
            low = mid + 1;
        } else {
            return mid;
        }
    }
    return -(low + 1);
}

std::vector<KeyRange> AddressMapImpl::getKeyRanges(const Address& start, const Address& end) {
    if (!start.hasSameAddressSpace(end) || start.getOffset() > end.getOffset()) {
        throw std::invalid_argument("Invalid start/end address range");
    }
    std::vector<KeyRange> keyRangeList;
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    int index = binarySearch(sortedBaseStartAddrs_, start);
    if (index < 0) {
        index = -index - 2;
    }
    if (index < 0) {
        index++;
    }
    while (index < static_cast<int>(sortedBaseStartAddrs_.size()) &&
           end >= sortedBaseStartAddrs_[index]) {
        Address addr1 = std::max(start, sortedBaseStartAddrs_[index]);
        Address addr2 = std::min(end, sortedBaseEndAddrs_[index]);
        if (addr1 <= addr2) {
            keyRangeList.push_back(KeyRange(getKey(addr1), getKey(addr2)));
        }
        index++;
    }
    return keyRangeList;
}

std::vector<KeyRange> AddressMapImpl::getKeyRanges(const AddressSetView* set) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<KeyRange> keyRangeList;
    if (set == nullptr) {
        for (size_t i = 0; i < sortedBaseStartAddrs_.size(); ++i) {
            keyRangeList.push_back(KeyRange(getKey(sortedBaseStartAddrs_[i]), getKey(sortedBaseEndAddrs_[i])));
        }
    } else {
        auto* rawIt = set->getAddressRanges();
        std::unique_ptr<AddressRangeIterator> it(rawIt);
        while (it && it->hasNext()) {
            const auto& range = it->next();
            std::vector<KeyRange> subRanges = getKeyRanges(range.getMinAddress(), range.getMaxAddress());
            keyRangeList.insert(keyRangeList.end(), subRanges.begin(), subRanges.end());
        }
    }
    return keyRangeList;
}

void AddressMapImpl::reconcile() {
    if (!addrFactory_) {
        return;
    }
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    std::unordered_map<std::string, OverlayAddressSpace*> remapSpaces;

    auto it = spaceMap_.begin();
    while (it != spaceMap_.end()) {
        std::string key = it->first;
        AddressSpace* space = it->second;
        auto* obs = dynamic_cast<ObsoleteOverlaySpace*>(space);
        if (obs) {
            OverlayAddressSpace* oldOverlaySpace = obs->getOriginalSpace();
            const AddressSpace* curSpace = addrFactory_->getAddressSpace(oldOverlaySpace->getName());
            if (curSpace != nullptr && *curSpace == *oldOverlaySpace) {
                remapSpaces[space->getName()] = const_cast<OverlayAddressSpace*>(dynamic_cast<const OverlayAddressSpace*>(curSpace));
                it = spaceMap_.erase(it);
                continue;
            }
        } else {
            auto* ov = dynamic_cast<OverlayAddressSpace*>(space);
            if (ov) {
                const AddressSpace* curSpace = addrFactory_->getAddressSpace(space->getName());
                if (curSpace == nullptr || !(*curSpace == *space)) {
                    auto obsolete = std::make_unique<ObsoleteOverlaySpace>(ov);
                    auto* obsPtr = obsolete.get();
                    std::string obsName = obsPtr->getName();
                    overlaySpaces_[obsName] = std::move(obsolete);
                    remapSpaces[space->getName()] = obsPtr;
                    it = spaceMap_.erase(it);
                    continue;
                }
            }
        }
        ++it;
    }

    for (const auto& pair : remapSpaces) {
        spaceMap_[pair.first] = pair.second;
    }

    for (size_t i = 0; i < baseAddrs_.size(); ++i) {
        Address addr = baseAddrs_[i];
        AddressSpace* space = addr.getAddressSpace();
        auto mapIt = remapSpaces.find(space->getName());
        if (mapIt != remapSpaces.end()) {
            baseAddrs_[i] = Address(mapIt->second, addr.getOffset());
        }
    }

    init();
}

} // namespace ghidra
