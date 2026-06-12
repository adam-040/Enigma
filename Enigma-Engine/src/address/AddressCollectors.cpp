/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AddressCollectors.cpp
#include "ghidra/AddressCollectors.h"

namespace ghidra {

AddressSet AddressCollectors::toAddressSet(const std::vector<AddressRange>& ranges) {
    AddressSet set;
    for (const AddressRange& r : ranges) {
        set.add(r);
    }
    return set;
}

} // namespace ghidra
