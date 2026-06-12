/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AbstractColorDataType.h
/// \brief Base type for fixed-length color data types.
#pragma once

#include "AbstractUnsignedIntegerDataType.h"
#include <string>
#include <vector>
#include <cstdint>

namespace ghidra {

class AbstractColorDataType : public AbstractUnsignedIntegerDataType {
public:
    struct ComponentValue {
        std::string name;
        int64_t value;
        int bitLength;

        ComponentValue(const std::string& n, int64_t v, int bl)
            : name(n), value(v), bitLength(bl) {}

        std::string getRepresentation(Settings* settings) const;
    };

    AbstractColorDataType(const std::string& name, DataTypeManager* dtm);

    AbstractIntegerDataType* getOppositeSignednessDataType() const override;

    const std::type_info& getValueClass(Settings* settings) const override;

    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override;

    std::string getValue(MemBuffer* buf, Settings* settings, int length) const;

    virtual std::string getEncodingName(Settings* settings) const = 0;
    virtual std::vector<ComponentValue> getComponentValues(MemBuffer* buf, Settings* settings) const = 0;
    virtual int decodeColor(MemBuffer* buf, Settings* settings) const = 0;

    static int getFieldValue(int64_t fullValue, int rightShift, int finalMask);
    static int scaleFieldValue(int value, int bitSize);

protected:
    static uint16_t readUInt16(MemBuffer* buf, Settings* settings);
    static uint32_t readUInt32(MemBuffer* buf, Settings* settings);
};

} // namespace ghidra
