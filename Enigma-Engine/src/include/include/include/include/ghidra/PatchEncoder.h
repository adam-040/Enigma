/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PatchEncoder.h
/// \brief Encoder that allows in-place patching of previously written attributes
/// Translated from: ghidra.program.model.pcode.PatchEncoder
#pragma once

#include <ghidra/CachedEncoder.h>
#include <cstdint>

namespace ghidra {

class AttributeId;

/// Encoder that allows previously written integer attributes to be patched in-place.
/// Use size() to record a position, then patchIntegerAttribute() to update it.
class PatchEncoder : public CachedEncoder {
public:
    virtual ~PatchEncoder() = default;

    /// Write a raw spaceid (as returned by AddressSpace::getSpaceID()) as an attribute.
    virtual void writeSpaceId(const AttributeId& attribId, int64_t spaceId) = 0;

    /// The current byte position in the stream. Can be passed to patchIntegerAttribute().
    virtual int size() const = 0;

    /// Replace an integer attribute at the given position with a new value.
    /// @return true if the attribute was successfully patched
    virtual bool patchIntegerAttribute(int pos, const AttributeId& attribId, int64_t val) = 0;
};

} // namespace ghidra
