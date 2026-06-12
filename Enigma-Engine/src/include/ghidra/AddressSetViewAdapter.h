/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AddressSetViewAdapter.h
/// \brief Read-only adapter wrapping an AddressSetView
/// Translated from: ghidra.program.model.address.AddressSetViewAdapter
#pragma once

#include <ghidra/AddressSetView.h>
#include <ghidra/AddressSet.h>
#include <memory>

namespace ghidra {

class AddressSetViewAdapter : public AddressSetView {
public:
    explicit AddressSetViewAdapter(const AddressSetView& set);
    AddressSetViewAdapter();

    bool contains(const Address& addr) const override;
    bool contains(const Address& start, const Address& end) const override;
    bool contains(const AddressSetView& rangeSet) const override;
    bool isEmpty() const override;
    Address getMinAddress() const override;
    Address getMaxAddress() const override;
    int getNumAddressRanges() const override;
    int64_t getNumAddresses() const override;
    AddressRangeIterator* getAddressRanges() const override;
    AddressRangeIterator* getAddressRanges(bool forward) const override;
    AddressRangeIterator* getAddressRanges(const Address& start, bool forward) const override;
    bool intersects(const AddressSetView& other) const override;
    bool intersects(const Address& start, const Address& end) const override;
    AddressSet intersect(const AddressSetView& view) const override;
    AddressSet intersectRange(const Address& start, const Address& end) const override;
    AddressSet unionSet(const AddressSetView& addrSet) const override;
    AddressSet subtract(const AddressSetView& addrSet) const override;
    AddressSet xorSet(const AddressSetView& addrSet) const override;
    bool hasSameAddresses(const AddressSetView& other) const override;
    AddressRange getFirstRange() const override;
    AddressRange getLastRange() const override;
    AddressRange getRangeContaining(const Address& address) const override;
    Address findFirstAddressInCommon(const AddressSetView& set) const override;

    bool equals(const AddressSetViewAdapter& other) const;
    int hashCode() const;
    std::string toString() const;

private:
    std::unique_ptr<AddressSetView> set_;
};

} // namespace ghidra
