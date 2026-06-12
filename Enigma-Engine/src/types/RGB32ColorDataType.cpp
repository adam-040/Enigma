/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/RGB32ColorDataType.h>
#include <ghidra/MemBuffer.h>
#include <ghidra/Settings.h>
#include <ghidra/TypeDefSettingsDefinition.h>
#include <cstdint>
#include <algorithm>

namespace ghidra {

RGB32ColorDataType RGB32ColorDataType::dataType;

RGB32ColorDataType::RGB32ColorDataType(DataTypeManager* dtm)
    : AbstractColorDataType("RGB32", dtm) {}

DataType* RGB32ColorDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<RGB32ColorDataType*>(this);
    }
    return new RGB32ColorDataType(dtm);
}

int RGB32ColorDataType::getLength() const {
    return LENGTH;
}

std::string RGB32ColorDataType::getDescription() const {
    return "An RGB color with 32-bit encoding (default encoding is ARGB_8888, use Typedef for other 32-bit encodings)";
}

std::string RGB32ColorDataType::getEncodingName(Settings* settings) const {
    auto encoding = RGB32EncodingSettingsDefinition::def().getRGBEncoding(settings);
    switch (encoding) {
        case RGB32EncodingSettingsDefinition::RGB32Encoding::ARGB_8888: return "ARGB_8888";
        case RGB32EncodingSettingsDefinition::RGB32Encoding::RGBA_8888: return "RGBA_8888";
        case RGB32EncodingSettingsDefinition::RGB32Encoding::BGRA_8888: return "BGRA_8888";
        case RGB32EncodingSettingsDefinition::RGB32Encoding::ABGR_8888: return "ABGR_8888";
    }
    return "ARGB_8888";
}

int RGB32ColorDataType::decodeColor(MemBuffer* buf, Settings* settings) const {
    uint32_t value = readUInt32(buf, settings);

    auto encoding = RGB32EncodingSettingsDefinition::def().getRGBEncoding(settings);
    switch (encoding) {
        case RGB32EncodingSettingsDefinition::RGB32Encoding::ARGB_8888:
            break;
        case RGB32EncodingSettingsDefinition::RGB32Encoding::RGBA_8888: {
            uint32_t alpha = value & 0xff;
            uint32_t rgb = value >> 8;
            value = rgb | (alpha << 24);
            break;
        }
        case RGB32EncodingSettingsDefinition::RGB32Encoding::BGRA_8888: {
            uint32_t a = (value >> 24) & 0xff;
            uint32_t r = (value >> 16) & 0xff;
            uint32_t g = (value >> 8) & 0xff;
            uint32_t b = value & 0xff;
            value = (a << 24) | (r << 16) | (g << 8) | b;
            break;
        }
        case RGB32EncodingSettingsDefinition::RGB32Encoding::ABGR_8888: {
            uint32_t a = (value >> 24) & 0xff;
            uint32_t b = (value >> 16) & 0xff;
            uint32_t g = (value >> 8) & 0xff;
            uint32_t r = value & 0xff;
            value = (a << 24) | (r << 16) | (g << 8) | b;
            break;
        }
    }

    // Return RGB packed (no alpha): (R<<16)|(G<<8)|B
    return static_cast<int>((value >> 16) & 0xff) << 16 |
           static_cast<int>((value >> 8) & 0xff) << 8 |
           static_cast<int>(value & 0xff);
}

std::vector<AbstractColorDataType::ComponentValue> RGB32ColorDataType::getComponentValues(
        MemBuffer* buf, Settings* settings) const {
    uint32_t value = readUInt32(buf, settings);
    std::vector<ComponentValue> list;

    auto encoding = RGB32EncodingSettingsDefinition::def().getRGBEncoding(settings);
    switch (encoding) {
        case RGB32EncodingSettingsDefinition::RGB32Encoding::ARGB_8888:
            list.emplace_back("A", getFieldValue(value, 24, 0xff), 8);
            list.emplace_back("R", getFieldValue(value, 16, 0xff), 8);
            list.emplace_back("G", getFieldValue(value, 8, 0xff), 8);
            list.emplace_back("B", getFieldValue(value, 0, 0xff), 8);
            break;
        case RGB32EncodingSettingsDefinition::RGB32Encoding::RGBA_8888:
            list.emplace_back("R", getFieldValue(value, 24, 0xff), 8);
            list.emplace_back("G", getFieldValue(value, 16, 0xff), 8);
            list.emplace_back("B", getFieldValue(value, 8, 0xff), 8);
            list.emplace_back("A", getFieldValue(value, 0, 0xff), 8);
            break;
        case RGB32EncodingSettingsDefinition::RGB32Encoding::BGRA_8888:
            list.emplace_back("B", getFieldValue(value, 24, 0xff), 8);
            list.emplace_back("G", getFieldValue(value, 16, 0xff), 8);
            list.emplace_back("R", getFieldValue(value, 8, 0xff), 8);
            list.emplace_back("A", getFieldValue(value, 0, 0xff), 8);
            break;
        case RGB32EncodingSettingsDefinition::RGB32Encoding::ABGR_8888:
            list.emplace_back("A", getFieldValue(value, 24, 0xff), 8);
            list.emplace_back("B", getFieldValue(value, 16, 0xff), 8);
            list.emplace_back("G", getFieldValue(value, 8, 0xff), 8);
            list.emplace_back("R", getFieldValue(value, 0, 0xff), 8);
            break;
    }
    return list;
}

std::vector<TypeDefSettingsDefinition*> RGB32ColorDataType::getTypeDefSettingsDefinitions() const {
    return {};
}

} // namespace ghidra
