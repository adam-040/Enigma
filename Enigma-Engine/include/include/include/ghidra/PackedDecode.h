/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PackedDecode.h
/// \brief Byte-based decoder using the packed binary format
/// Translated from: ghidra.program.model.pcode.PackedDecode
#pragma once

#include <ghidra/Decoder.h>
#include <cstdint>
#include <vector>

namespace ghidra {

/// Decoder for the packed binary format produced by PackedEncode.
/// Uses a simple in-memory byte vector as the backing store (no streaming).
class PackedDecode : public Decoder {
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
    AddressFactory* addrFactory_;
    const AddressSpace** spaces_;
    int spacesCount_;
private:
    std::vector<uint8_t> buf_;
    int startPos_;
    int curPos_;
    int endPos_;
    int bufSize_;
    bool attributeRead_;

    void buildAddrSpaceArray();
    int64_t readIntegerBytes(int len);
    int readHeaderId(int pos, int& outId);

    int skipAttributeAt(int pos);
    int readIntAt(int pos, int len, int& outVal);

public:
    PackedDecode();
    explicit PackedDecode(AddressFactory* addrFactory);
    ~PackedDecode() override;

    void ingest(const uint8_t* bytes, int len);
    void ingest(const std::vector<uint8_t>& bytes);

    AddressFactory* getAddressFactory() override { return addrFactory_; }
    void setAddressFactory(AddressFactory* addrFactory) override;

    int peekElement() override;
    int openElement() override;
    int openElement(const ElementId& elemId) override;
    void closeElement() override;
    void closeElement(int id) override;

    int getNextAttributeId() override;

    bool readBool() override;
    bool readBool(int id) override;
    bool readBool(AttributeId id) override;
    int64_t readSignedInteger() override;
    int64_t readSignedInteger(int id) override;
    int64_t readSignedInteger(AttributeId id) override;
    uint64_t readUnsignedInteger() override;
    uint64_t readUnsignedInteger(int id) override;
    uint64_t readUnsignedInteger(AttributeId id) override;
    std::string readString() override;
    std::string readString(int id) override;
    std::string readString(AttributeId id) override;

    AddressSpace* readSpace() override;
    AddressSpace* readSpace(const AttributeId& attribId) override;
    AddressSpace* readSpace(int id);

    void skipElement() override;
    void rewindAttributes() override;

    uint8_t readByte() override;
    std::vector<uint8_t> readBytes(int count) override;
};

} // namespace ghidra
