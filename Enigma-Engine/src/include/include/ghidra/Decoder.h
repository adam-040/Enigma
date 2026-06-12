#pragma once

#include <ghidra/AddressFactory.h>
#include <ghidra/AttributeId.h>
#include <ghidra/ElementId.h>
#include <ghidra/AddressSpace.h>
#include <vector>
#include <string>
#include <cstdint>

namespace ghidra {

class DecoderException;

class Decoder {
public:
    virtual ~Decoder() = default;

    virtual AddressFactory* getAddressFactory() = 0;
    virtual void setAddressFactory(AddressFactory* addrFactory) = 0;

    virtual int peekElement() = 0;
    virtual int openElement() = 0;
    virtual int openElement(const ElementId& elemId) = 0;
    virtual void closeElement() = 0;
    virtual void closeElement(int id) = 0;
    virtual void skipElement() = 0;
    virtual void rewindAttributes() = 0;

    virtual int getNextAttributeId() = 0;
    virtual bool readBool() = 0;
    virtual int64_t readSignedInteger() = 0;
    virtual uint64_t readUnsignedInteger() = 0;
    virtual std::string readString() = 0;
    virtual std::string readString(int id) = 0;
    virtual uint64_t readUnsignedInteger(int id) = 0;
    virtual int64_t readSignedInteger(int id) = 0;
    virtual bool readBool(int id) = 0;
    virtual bool readBool(AttributeId id) = 0;
    virtual uint64_t readUnsignedInteger(AttributeId id) = 0;
    virtual int64_t readSignedInteger(AttributeId id) = 0;
    virtual std::string readString(AttributeId id) = 0;

    virtual AddressSpace* readSpace() = 0;
    virtual AddressSpace* readSpace(const AttributeId& attribId) = 0;

    // Stream read methods (readByte/readBytes) used internally.
    virtual uint8_t readByte() = 0;
    virtual std::vector<uint8_t> readBytes(int count) = 0;
};

} // namespace ghidra
