/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AddressSetCollection.cpp
/// \brief Collection of address sets
/// Translated from: ghidra.program.model.address.AddressSetCollection

#include <ghidra/AddressSetCollection.h>
#include <ghidra/AddressSet.h>
#include <algorithm>

namespace ghidra {

class AddressSetCollectionImpl : public AddressSetCollection {
private:
    std::vector<AddressSet> sets_;

public:
    void addSet(const AddressSet& set) { sets_.push_back(set); }
    void clear() { sets_.clear(); }
    int size() const { return static_cast<int>(sets_.size()); }

    bool intersects(const AddressSetView& addrSet) override {
        for (const auto& set : sets_) {
            if (set.intersects(addrSet)) return true;
        }
        return false;
    }

    bool intersects(const Address& start, const Address& end) override {
        for (const auto& set : sets_) {
            if (set.intersects(start, end)) return true;
        }
        return false;
    }

    bool contains(const Address& address) override {
        for (const auto& set : sets_) {
            if (set.contains(address)) return true;
        }
        return false;
    }

    bool hasFewerRangesThan(int rangeThreshold) override {
        int total = 0;
        for (const auto& set : sets_) {
            total += set.getNumAddressRanges();
            if (total >= rangeThreshold) return false;
        }
        return true;
    }

    AddressSet getCombinedAddressSet() override {
        AddressSet result;
        for (const auto& set : sets_) {
            result = result.unionSet(set);
        }
        return result;
    }

    Address findFirstAddressInCommon(const AddressSetView& set) override {
        for (const auto& addrSet : sets_) {
            Address addr = addrSet.findFirstAddressInCommon(set);
            if (addr.getAddressSpace()) return addr;
        }
        return Address();
    }

    bool isEmpty() override {
        for (const auto& set : sets_) {
            if (!set.isEmpty()) return false;
        }
        return true;
    }

    Address getMinAddress() override {
        Address minAddr;
        for (const auto& set : sets_) {
            if (!set.isEmpty()) {
                Address addr = set.getMinAddress();
                if (!minAddr.getAddressSpace() || addr < minAddr) {
                    minAddr = addr;
                }
            }
        }
        return minAddr;
    }

    Address getMaxAddress() override {
        Address maxAddr;
        for (const auto& set : sets_) {
            if (!set.isEmpty()) {
                Address addr = set.getMaxAddress();
                if (!maxAddr.getAddressSpace() || addr > maxAddr) {
                    maxAddr = addr;
                }
            }
        }
        return maxAddr;
    }
};

} // namespace ghidra
