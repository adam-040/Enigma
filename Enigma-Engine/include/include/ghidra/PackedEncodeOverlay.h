/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PackedEncodeOverlay.h
/// \brief PackedEncode that maps address spaces through an overlay
/// Translated from: ghidra.program.model.pcode.PackedEncodeOverlay
#pragma once

#include <ghidra/PackedEncode.h>

namespace ghidra {

class PackedEncodeOverlay : public PackedEncode {
public:
    PackedEncodeOverlay() = default;

    void writeSpace(const AttributeId& attribId, const AddressSpace* spc) override;

    void writeSpace(const AttributeId& attribId, int index, const std::string& name);
};

} // namespace ghidra
