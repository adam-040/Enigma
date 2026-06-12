/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AddressCollectors.h
/// \brief Utility for collecting address ranges into an AddressSet.
/// Translated from: ghidra.program.model.address.AddressCollectors
#pragma once

#include "ghidra/AddressSet.h"
#include "ghidra/AddressRange.h"
#include <functional>

namespace ghidra {

/// Utility namespace for collecting address ranges into an AddressSet.
class AddressCollectors {
public:
    /// Build an AddressSet by adding all ranges from a source container.
    static AddressSet toAddressSet(const std::vector<AddressRange>& ranges);
};

} // namespace ghidra
