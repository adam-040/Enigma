/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PackedEncode.h
/// \brief Byte-based encoder using a packed binary format
/// Translated from: ghidra.program.model.pcode.PackedEncode
#pragma once

#include <ghidra/Encoder.h>
#include <ghidra/PackedBytes.h>
#include <vector>

namespace ghidra {

/// Byte-based encoder that writes structured elements/attributes in the
/// packed format described by PackedDecode. The backing store is a
/// PackedBytes instance (in-memory). To write to an arbitrary stream,
/// use getBytes() and copy.
class PackedEncode : public Encoder {
public:
    static constexpr int HEADER_MASK = 0xc0;
    static constexpr int ELEMENT_START = 0x40;
    static constexpr int ELEMENT_END = 0x80;
    static constexpr int ATTRIBUTE = 0xc0;
    static constexpr int HEADEREXTEND_MASK = 0x20;
    static constexpr int ELEMENTID_MASK = 0x1f;
    static constexpr int RAWDATA_MASK = 0x7f;
    static constexpr int RAWDATA_BITSPERBYTE = 7;
    static constexpr int RAWDATA_MARKER = 0x80;
    static constexpr int TYPECODE_SHIFT = 4;
    static constexpr int LENGTHCODE_MASK = 0xf;
    static constexpr int TYPECODE_BOOLEAN = 1;
    static constexpr int TYPECODE_SIGNEDINT_POSITIVE = 2;
    static constexpr int TYPECODE_SIGNEDINT_NEGATIVE = 3;
    static constexpr int TYPECODE_UNSIGNEDINT = 4;
    static constexpr int TYPECODE_ADDRESSSPACE = 5;
    static constexpr int TYPECODE_SPECIALSPACE = 6;
    static constexpr int TYPECODE_STRING = 7;
    static constexpr int SPECIALSPACE_STACK = 0;
    static constexpr int SPECIALSPACE_JOIN = 1;
    static constexpr int SPECIALSPACE_FSPEC = 2;
    static constexpr int SPECIALSPACE_IOP = 3;
    static constexpr int SPECIALSPACE_SPACEBASE = 4;

protected:
    PackedBytes outStream_;

    void writeHeader(int header, int id);
    void writeInteger(int typeByte, int64_t val);

public:
    PackedEncode();
    ~PackedEncode() override = default;

    void openElement(const ElementId& elemId) override;
    void closeElement(const ElementId& elemId) override;

    void writeBool(const AttributeId& attribId, bool val) override;
    void writeSignedInteger(const AttributeId& attribId, int64_t val) override;
    void writeUnsignedInteger(const AttributeId& attribId, uint64_t val) override;
    void writeString(const AttributeId& attribId, const std::string& val) override;
    void writeSpace(const AttributeId& attribId, const AddressSpace* spc) override;

    void writeStringIndexed(const AttributeId& attribId, int index, const std::string& val);
    void writeSpace(const AttributeId& attribId, int index, const std::string& name);

    PackedBytes& getPackedBytes() { return outStream_; }
    const PackedBytes& getPackedBytes() const { return outStream_; }
    void getBytes(std::vector<uint8_t>& dst) const;
    int size() const { return outStream_.size(); }
    void clear();
};

} // namespace ghidra
