/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SingleAddressSetCollection.h
/// \brief Simple AddressSetCollection containing exactly one AddressSet
/// Translated from: ghidra.program.model.address.SingleAddressSetCollection
#pragma once

#include <ghidra/AddressSetCollection.h>
#include <ghidra/AddressSet.h>

namespace ghidra {

class SingleAddressSetCollection : public AddressSetCollection {
public:
    explicit SingleAddressSetCollection(const AddressSetView& set);

    bool intersects(const AddressSetView& addrSet) override;
    bool intersects(const Address& start, const Address& end) override;
    bool contains(const Address& address) override;
    bool hasFewerRangesThan(int rangeThreshold) override;
    AddressSet getCombinedAddressSet() override;
    Address findFirstAddressInCommon(const AddressSetView& set) override;
    bool isEmpty() override;
    Address getMinAddress() override;
    Address getMaxAddress() override;

private:
    AddressSet set_;
};

} // namespace ghidra
