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

#include "ghidra/Address.h"
#include "ghidra/AddressSetView.h"
#include "ghidra/Duo.h"

namespace ghidra {

class Function;
class Program;

class ListingAddressCorrelation {
public:
    virtual ~ListingAddressCorrelation() = default;

    virtual Program* getProgram(Side side) = 0;
    virtual AddressSetView* getAddresses(Side side) = 0;
    virtual Address getAddress(Side side, Address otherSideAddress) = 0;
    virtual Function* getFunction(Side side) = 0;
};

} // namespace ghidra
