/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ImmutableAddressSet.h
/// \brief Immutable implementation of AddressSetView
/// Translated from: ghidra.program.model.address.ImmutableAddressSet
#pragma once

#include <ghidra/AddressSetView.h>
#include <ghidra/AddressSet.h>
#include <memory>

namespace ghidra {

class ImmutableAddressSet : public AddressSetView {
public:
    static const ImmutableAddressSet& EMPTY_SET();

    static ImmutableAddressSet asImmutable(const AddressSetView* view);

    explicit ImmutableAddressSet(const AddressSetView& addresses);
    explicit ImmutableAddressSet(const AddressSet& addresses);

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

    bool equals(const ImmutableAddressSet& other) const;
    int hashCode() const;

private:
    AddressSet set_;
};

} // namespace ghidra
