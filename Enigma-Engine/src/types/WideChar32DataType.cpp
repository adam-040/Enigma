/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file WideChar32DataType.cpp
#include "ghidra/WideChar32DataType.h"
#include "ghidra/AbstractStringDataType.h"
#include "ghidra/CategoryPath.h"
#include "ghidra/DataTypeDisplayOptions.h"
#include "ghidra/DataTypeManager.h"
#include "ghidra/EndianSettingsDefinition.h"
#include "ghidra/MemBuffer.h"
#include "ghidra/RenderUnicodeSettingsDefinition.h"
#include "ghidra/Settings.h"
#include "ghidra/SettingsDefinition.h"
#include "ghidra/StringDataInstance.h"
#include "ghidra/TranslationSettingsDefinition.h"
#include <cstdio>

namespace ghidra {

WideChar32DataType& WideChar32DataType::dataType() {
    static WideChar32DataType instance;
    return instance;
}

WideChar32DataType::WideChar32DataType(DataTypeManager* dtm)
    : BuiltIn(CategoryPath::ROOT(), "wchar32", dtm) {}

DataType* WideChar32DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<WideChar32DataType*>(this);
    }
    return new WideChar32DataType(dtm);
}

int WideChar32DataType::getLength() const {
    return 4;
}

std::string WideChar32DataType::getDescription() const {
    return "Wide-Character (32-bit/UTF32)";
}

std::string WideChar32DataType::getMnemonic(Settings* settings) const {
    (void)settings;
    return "wchar32";
}

std::string WideChar32DataType::getRepresentation(MemBuffer* buf, Settings* settings,
                                                    int length) const {
    return StringDataInstance(const_cast<WideChar32DataType*>(this), settings, buf, getLength())
        .getCharRepresentation();
}

std::string WideChar32DataType::getDefaultLabelPrefix() const {
    return "WCHAR32";
}

std::string WideChar32DataType::getDefaultLabelPrefix(MemBuffer* buf, Settings* settings,
                                                        int length,
                                                        DataTypeDisplayOptions* options) const {
    (void)length; (void)options;
    std::string str = "WCHAR32_";
    if (buf == nullptr) return str + "??";
    try {
        int val = buf->getInt(0);
        if (val >= 0x20 && val < 0x7F) {
            str += static_cast<char>(val);
        } else {
            char hex[16];
            std::snprintf(hex, sizeof(hex), "%x", val);
            str += hex;
            str += 'h';
        }
    } catch (...) {
        str += "??";
    }
    return str;
}

std::vector<SettingsDefinition*> WideChar32DataType::getSettingsDefinitions() const {
    return {
        const_cast<EndianSettingsDefinition*>(&EndianSettingsDefinition::def()),
        const_cast<RenderUnicodeSettingsDefinition*>(&RenderUnicodeSettingsDefinition::def()),
        const_cast<TranslationSettingsDefinition*>(&TranslationSettingsDefinition::def())
    };
}

const std::type_info& WideChar32DataType::getValueClass(Settings* settings) const {
    (void)settings;
    return typeid(int);
}

std::vector<uint8_t> WideChar32DataType::encodeValue(void* value, MemBuffer* buf,
                                                       Settings* settings, int length) const {
    (void)value; (void)buf; (void)settings; (void)length;
    return {};
}

std::vector<uint8_t> WideChar32DataType::encodeRepresentation(const std::string& repr,
                                                               MemBuffer* buf, Settings* settings,
                                                               int length) const {
    (void)repr; (void)buf; (void)settings; (void)length;
    return {};
}

std::string WideChar32DataType::getCharsetName(Settings* settings) const {
    (void)settings;
    return CharsetInfoManager::UTF32;
}

bool WideChar32DataType::hasStringValue(Settings* settings) const {
    (void)settings;
    return true;
}

std::string WideChar32DataType::getArrayDefaultLabelPrefix(MemBuffer* buf, Settings* settings,
                                                             int len,
                                                             const DataTypeDisplayOptions& options) const {
    return StringDataInstance(const_cast<WideChar32DataType*>(this), settings, buf, len, true)
        .getLabel(AbstractStringDataType::DEFAULT_UNICODE_ABBREV_PREFIX + "_",
                  AbstractStringDataType::DEFAULT_UNICODE_LABEL_PREFIX,
                  AbstractStringDataType::DEFAULT_UNICODE_LABEL, options);
}

std::string WideChar32DataType::getArrayDefaultOffcutLabelPrefix(MemBuffer* buf, Settings* settings,
                                                                   int len,
                                                                   const DataTypeDisplayOptions& options,
                                                                   int offcutLength) const {
    return StringDataInstance(const_cast<WideChar32DataType*>(this), settings, buf, len, true)
        .getOffcutLabelString(AbstractStringDataType::DEFAULT_UNICODE_ABBREV_PREFIX + "_",
                              AbstractStringDataType::DEFAULT_UNICODE_LABEL_PREFIX,
                              AbstractStringDataType::DEFAULT_UNICODE_LABEL, options,
                              offcutLength);
}

} // namespace ghidra
