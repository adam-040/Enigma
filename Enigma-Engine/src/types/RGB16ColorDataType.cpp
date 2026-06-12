/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/RGB16ColorDataType.h>
#include <ghidra/MemBuffer.h>
#include <ghidra/Settings.h>
#include <ghidra/TypeDefSettingsDefinition.h>
#include <cstdint>

namespace ghidra {

RGB16ColorDataType RGB16ColorDataType::dataType;

RGB16ColorDataType::RGB16ColorDataType(DataTypeManager* dtm)
    : AbstractColorDataType("RGB16", dtm) {}

DataType* RGB16ColorDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<RGB16ColorDataType*>(this);
    }
    return new RGB16ColorDataType(dtm);
}

int RGB16ColorDataType::getLength() const {
    return LENGTH;
}

std::string RGB16ColorDataType::getDescription() const {
    return "An RGB color with 16-bit encoding (default encoding is RGB_565, use Typedef for other 16-bit encodings)";
}

std::string RGB16ColorDataType::getEncodingName(Settings* settings) const {
    auto encoding = RGB16EncodingSettingsDefinition::def().getRGBEncoding(settings);
    switch (encoding) {
        case RGB16EncodingSettingsDefinition::RGB16Encoding::RGB_565: return "RGB_565";
        case RGB16EncodingSettingsDefinition::RGB16Encoding::RGB_555: return "RGB_555";
        case RGB16EncodingSettingsDefinition::RGB16Encoding::ARGB_1555: return "ARGB_1555";
    }
    return "RGB_565";
}

int RGB16ColorDataType::decodeColor(MemBuffer* buf, Settings* settings) const {
    int value = readUInt16(buf, settings);
    int argb = 0;

    auto encoding = RGB16EncodingSettingsDefinition::def().getRGBEncoding(settings);
    switch (encoding) {
        case RGB16EncodingSettingsDefinition::RGB16Encoding::RGB_565: {
            int r = scaleFieldValue(getFieldValue(value, 11, 0x1f), 5);
            int g = scaleFieldValue(getFieldValue(value, 5, 0x3f), 6);
            int b = scaleFieldValue(getFieldValue(value, 0, 0x1f), 5);
            argb = (r << 16) | (g << 8) | b;
            break;
        }
        case RGB16EncodingSettingsDefinition::RGB16Encoding::RGB_555: {
            int r = scaleFieldValue(getFieldValue(value, 10, 0x1f), 5);
            int g = scaleFieldValue(getFieldValue(value, 5, 0x1f), 5);
            int b = scaleFieldValue(getFieldValue(value, 0, 0x1f), 5);
            argb = (r << 16) | (g << 8) | b;
            break;
        }
        case RGB16EncodingSettingsDefinition::RGB16Encoding::ARGB_1555: {
            int a = getFieldValue(value, 15, 0x1);
            int r = scaleFieldValue(getFieldValue(value, 10, 0x1f), 5);
            int g = scaleFieldValue(getFieldValue(value, 5, 0x1f), 5);
            int b = scaleFieldValue(getFieldValue(value, 0, 0x1f), 5);
            argb = (a << 24) | (r << 16) | (g << 8) | b;
            break;
        }
    }
    return argb;
}

std::vector<AbstractColorDataType::ComponentValue> RGB16ColorDataType::getComponentValues(
        MemBuffer* buf, Settings* settings) const {
    int value = readUInt16(buf, settings);
    std::vector<ComponentValue> list;

    auto encoding = RGB16EncodingSettingsDefinition::def().getRGBEncoding(settings);
    switch (encoding) {
        case RGB16EncodingSettingsDefinition::RGB16Encoding::RGB_565:
            list.emplace_back("R", getFieldValue(value, 11, 0x1f), 5);
            list.emplace_back("G", getFieldValue(value, 5, 0x3f), 6);
            list.emplace_back("B", getFieldValue(value, 0, 0x1f), 5);
            break;
        case RGB16EncodingSettingsDefinition::RGB16Encoding::RGB_555:
            list.emplace_back("R", getFieldValue(value, 10, 0x1f), 5);
            list.emplace_back("G", getFieldValue(value, 5, 0x1f), 5);
            list.emplace_back("B", getFieldValue(value, 0, 0x1f), 5);
            break;
        case RGB16EncodingSettingsDefinition::RGB16Encoding::ARGB_1555:
            list.emplace_back("A", getFieldValue(value, 15, 0x1), 1);
            list.emplace_back("R", getFieldValue(value, 10, 0x1f), 5);
            list.emplace_back("G", getFieldValue(value, 5, 0x1f), 5);
            list.emplace_back("B", getFieldValue(value, 0, 0x1f), 5);
            break;
    }
    return list;
}

std::vector<TypeDefSettingsDefinition*> RGB16ColorDataType::getTypeDefSettingsDefinitions() const {
    return {};
}

} // namespace ghidra
