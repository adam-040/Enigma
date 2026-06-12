/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file XmlDecode.h
/// \brief XML based decoder
#pragma once

#include <ghidra/Decoder.h>
#include <ghidra/XmlPullParser.h>
#include <ghidra/DecoderException.h>
#include <vector>
#include <unordered_map>
#include <sstream>

namespace ghidra {

class XmlDecode : public Decoder {
public:
    XmlDecode();
    explicit XmlDecode(AddressFactory* addrFactory);
    ~XmlDecode() override = default;

    // ByteIngest implementation
    uint8_t readByte() override { return 0; }
    std::vector<uint8_t> readBytes(int count) override { return {}; }

    // Decoder implementation
    AddressFactory* getAddressFactory() override { return addrFactory_; }
    void setAddressFactory(AddressFactory* addrFactory) override { addrFactory_ = addrFactory; }

    void ingestStream(std::istream& s);
    void ingestString(const std::string& s);

    int peekElement() override;
    int openElement() override;
    int openElement(const ElementId& elemId) override;
    void closeElement() override;
    void closeElement(int id) override;

    int getNextAttributeId() override;
    bool readBool() override;
    int64_t readSignedInteger() override;
    uint64_t readUnsignedInteger() override;
    std::string readString() override;

    std::string readString(int id) override;
    uint64_t readUnsignedInteger(int id) override;
    int64_t readSignedInteger(int id) override;
    bool readBool(int id) override;

    bool readBool(AttributeId id) override;
    uint64_t readUnsignedInteger(AttributeId id) override;
    int64_t readSignedInteger(AttributeId id) override;
    std::string readString(AttributeId id) override;

    AddressSpace* readSpace() override;
    AddressSpace* readSpace(const AttributeId& attribId) override;

    void skipElement() override;
    void rewindAttributes() override;

private:
    struct ElementFrame {
        XmlElement element;
        std::vector<std::string> attribKeys;
        size_t attribIndex = 0;
        std::string currentAttribKey;
        int elementId = 0;
    };

    AddressFactory* addrFactory_ = nullptr;
    XmlPullParser parser_;
    std::vector<ElementFrame> stack_;

    static int resolveElementId(const std::string& name);
    static int resolveAttributeId(const std::string& name);
    static uint64_t parseInteger(const std::string& val);
};

} // namespace ghidra
