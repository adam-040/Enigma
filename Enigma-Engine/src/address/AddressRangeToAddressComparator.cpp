/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AddressRangeToAddressComparator.cpp
#include "ghidra/AddressRangeToAddressComparator.h"

namespace ghidra {

int AddressRangeToAddressComparator::compareRangeToAddress(const AddressRange* range,
                                                           const Address* addr) const {
    if (range == nullptr || addr == nullptr) return 0;
    return range->compareTo(*addr);
}

} // namespace ghidra
