/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Encoder.h
/// \brief Base class for encoding program model structures to stream
#pragma once

#include <ghidra/ElementId.h>
#include <ghidra/AttributeId.h>
#include <ghidra/AddressSpace.h>
#include <string>
#include <cstdint>

namespace ghidra {

class Encoder {
public:
    virtual ~Encoder() = default;

    virtual void openElement(const ElementId& elemId) = 0;
    virtual void closeElement(const ElementId& elemId) = 0;

    virtual void writeBool(const AttributeId& attribId, bool val) = 0;
    virtual void writeSignedInteger(const AttributeId& attribId, int64_t val) = 0;
    virtual void writeUnsignedInteger(const AttributeId& attribId, uint64_t val) = 0;
    virtual void writeString(const AttributeId& attribId, const std::string& val) = 0;
    virtual void writeSpace(const AttributeId& attribId, const AddressSpace* spc) = 0;
};

} // namespace ghidra
