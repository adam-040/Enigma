/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PackedDecodeOverlay.h
/// \brief PackedDecode that supports overlay address space substitution
/// Translated from: ghidra.program.model.pcode.PackedDecodeOverlay
#pragma once

#include <ghidra/PackedDecode.h>

namespace ghidra {

class PackedDecodeOverlay : public PackedDecode {
public:
    PackedDecodeOverlay(AddressFactory* addrFactory, AddressSpace* spc);

    void setOverlay(AddressSpace* spc);
};

} // namespace ghidra
