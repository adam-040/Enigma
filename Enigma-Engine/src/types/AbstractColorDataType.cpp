/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/AbstractColorDataType.h>
#include <ghidra/EndianSettingsDefinition.h>
#include <ghidra/MemBuffer.h>
#include <ghidra/Settings.h>
#include <sstream>
#include <iomanip>

namespace ghidra {

AbstractColorDataType::AbstractColorDataType(const std::string& name, DataTypeManager* dtm)
    : AbstractUnsignedIntegerDataType(name, dtm) {}

AbstractIntegerDataType* AbstractColorDataType::getOppositeSignednessDataType() const {
    return const_cast<AbstractColorDataType*>(this);
}

const std::type_info& AbstractColorDataType::getValueClass(Settings* settings) const {
    return typeid(int);
}

std::string AbstractColorDataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    int size = getLength();
    if (size <= 0) return "??";

    uint8_t tmp[8] = {};
    uint8_t* bytes = tmp;
    std::vector<uint8_t> vec;
    if (size > 8) {
        vec.resize(size);
        bytes = vec.data();
    }
    if (buf->getBytes(bytes, size, 0) != size) {
        return "??";
    }

    bool bigEndian = EndianSettingsDefinition::ENDIAN->isBigEndian(settings, buf);
    uint64_t val = 0;
    if (bigEndian) {
        for (int i = 0; i < size; ++i) {
            val = (val << 8) | bytes[i];
        }
    } else {
        for (int i = size - 1; i >= 0; --i) {
            val = (val << 8) | bytes[i];
        }
    }

    std::ostringstream oss;
    oss << getEncodingName(settings) << " 0x"
        << std::hex << std::uppercase << std::setfill('0')
        << std::setw(size * 2) << val;
    oss << " {";
    int cnt = 0;
    for (const auto& cv : getComponentValues(buf, settings)) {
        if (cnt++ != 0) oss << ",";
        oss << cv.getRepresentation(settings);
    }
    oss << "}";
    return oss.str();
}

std::string AbstractColorDataType::getValue(MemBuffer* buf, Settings* settings, int length) const {
    int size = getLength();
    if (size < 1 || size > 8) return "??";
    return std::to_string(decodeColor(buf, settings));
}

int AbstractColorDataType::getFieldValue(int64_t fullValue, int rightShift, int finalMask) {
    return static_cast<int>((static_cast<uint64_t>(fullValue) >> rightShift) & static_cast<uint64_t>(finalMask));
}

int AbstractColorDataType::scaleFieldValue(int value, int bitSize) {
    return (value * 255) / ((1 << bitSize) - 1);
}

uint16_t AbstractColorDataType::readUInt16(MemBuffer* buf, Settings* settings) {
    return buf->getUnsignedShort(0);
}

uint32_t AbstractColorDataType::readUInt32(MemBuffer* buf, Settings* settings) {
    return buf->getUnsignedInt(0);
}

std::string AbstractColorDataType::ComponentValue::getRepresentation(Settings* settings) const {
    std::ostringstream oss;
    oss << name << ":0x" << std::hex << std::uppercase
        << std::setfill('0') << std::setw((bitLength + 3) / 4)
        << static_cast<uint64_t>(value);
    return oss.str();
}

} // namespace ghidra
