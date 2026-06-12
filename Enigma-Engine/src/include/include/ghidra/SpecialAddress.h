/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SpecialAddress.h
/// \brief Factory for named special addresses
/// Translated from: ghidra.program.model.address.SpecialAddress
#pragma once

#include <ghidra/Address.h>
#include <string>

namespace ghidra {

class SpecialAddress {
public:
    static Address create(const std::string& name);
};

} // namespace ghidra
