/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once

#include <ghidra/AbstractAddressSetView.h>
#include <ghidra/AddressMapImpl.h>
#include <ghidra/util/datastruct/SortedRangeList.h>
#include <unordered_map>
#include <vector>
#include <string>

namespace ghidra {

/**
 * AddressSetView implementation that handles image base changes.
 * Assumes that only address ranges that are part of the memory map will be added.
 */
class NormalizedAddressSet : public AbstractAddressSetView {
public:
    NormalizedAddressSet();
    explicit NormalizedAddressSet(AddressMap* addrMap);
    virtual ~NormalizedAddressSet() override = default;

    // Mutators
    void add(const Address& addr);
    void add(const AddressSetView& set);
    void add(const AddressRange& range);
    void addRange(const Address& startAddr, const Address& endAddr);
    void clear();
    void deleteSet(const AddressSetView& view);
    void remove(const AddressSetView& view) { deleteSet(view); }

    // AddressSetView overrides
    bool contains(const Address& addr) const override;
    bool isEmpty() const override;
    int getNumAddressRanges() const override;
    int64_t getNumAddresses() const override;

    // String representation
    std::string toString() const;

protected:
    std::vector<AddressRange> getRanges() const override;

private:
    void addKeyRange(uint64_t minKey, uint64_t maxKey);
    void deleteKeyRange(uint64_t minKey, uint64_t maxKey);

    AddressMapImpl* addrMap_ = nullptr;
    std::unordered_map<uint64_t, SortedRangeList> baseLists_;
    std::vector<uint64_t> bases_;
};

} // namespace ghidra
