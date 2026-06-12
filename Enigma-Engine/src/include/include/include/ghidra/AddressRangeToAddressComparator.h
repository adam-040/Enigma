/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AddressRangeToAddressComparator.h
/// \brief Compares an address against an address range.
/// Translated from: ghidra.program.model.address.AddressRangeToAddressComparator
#pragma once

#include "ghidra/Address.h"
#include "ghidra/AddressRange.h"

namespace ghidra {

/// Compares an address against an address range. Exactly one of obj1/obj2
/// must be an AddressRange, the other an Address.
class AddressRangeToAddressComparator {
public:
    /// @param range the AddressRange (or null)
    /// @param addr the Address (or null)
    /// @return negative/zero/positive as range < addr, ==, or >
    int compareRangeToAddress(const AddressRange* range, const Address* addr) const;
};

} // namespace ghidra
