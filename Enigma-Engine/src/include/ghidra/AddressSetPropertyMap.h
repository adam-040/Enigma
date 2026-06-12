/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AddressSetPropertyMap.h
/// \brief Address set property map interface for marking address ranges
/// Translated from: ghidra.program.model.util.AddressSetPropertyMap
#pragma once

#include <ghidra/Address.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AddressIterator.h>
#include <ghidra/AddressRangeIterator.h>
#include <string>

namespace ghidra {

class AddressSetPropertyMap {
public:
    virtual ~AddressSetPropertyMap() = default;

    virtual const std::string& getName() const = 0;

    virtual void add(const Address& start, const Address& end) = 0;
    virtual void add(const AddressSetView& addressSet) = 0;
    virtual void set(const AddressSetView& addressSet) = 0;

    virtual void remove(const Address& start, const Address& end) = 0;
    virtual void remove(const AddressSetView& addressSet) = 0;

    virtual AddressSet getAddressSet() = 0;
    virtual AddressIterator* getAddresses() = 0;
    virtual AddressRangeIterator* getAddressRanges() = 0;

    virtual void clear() = 0;
    virtual bool contains(const Address& addr) = 0;
};

} // namespace ghidra
