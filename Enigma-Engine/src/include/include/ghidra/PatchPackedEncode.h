/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PatchPackedEncode.h
/// \brief PackedEncode that supports in-place patching of integer attributes
/// Translated from: ghidra.program.model.pcode.PatchPackedEncode
#pragma once

#include <ghidra/PatchEncoder.h>
#include <ghidra/PackedEncode.h>
#include <ghidra/AddressSpace.h>

namespace ghidra {

class PatchPackedEncode : public PackedEncode, public PatchEncoder {
public:
    PatchPackedEncode() = default;
    ~PatchPackedEncode() override = default;

    void openElement(const ElementId& elemId) override;
    void closeElement(const ElementId& elemId) override;
    void writeBool(const AttributeId& attribId, bool val) override;
    void writeSignedInteger(const AttributeId& attribId, int64_t val) override;
    void writeUnsignedInteger(const AttributeId& attribId, uint64_t val) override;
    void writeString(const AttributeId& attribId, const std::string& val) override;
    void writeSpace(const AttributeId& attribId, const AddressSpace* spc) override;

    int size() const override { return outStream_.size(); }

    void writeSpaceId(const AttributeId& attribId, int64_t spaceId) override;
    bool patchIntegerAttribute(int pos, const AttributeId& attribId, int64_t val) override;

    void clear() override;
    bool isEmpty() const override;
    void writeTo(std::ostream& stream) override;
};

} // namespace ghidra
