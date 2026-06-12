/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file WideChar16DataType.cpp
#include "ghidra/WideChar16DataType.h"
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

namespace ghidra {

WideChar16DataType& WideChar16DataType::dataType() {
    static WideChar16DataType instance;
    return instance;
}

WideChar16DataType::WideChar16DataType(DataTypeManager* dtm)
    : BuiltIn(CategoryPath::ROOT(), "wchar16", dtm) {}

DataType* WideChar16DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<WideChar16DataType*>(this);
    }
    return new WideChar16DataType(dtm);
}

int WideChar16DataType::getLength() const {
    return 2;
}

std::string WideChar16DataType::getDescription() const {
    return "Wide-Character (16-bit/UTF16)";
}

std::string WideChar16DataType::getMnemonic(Settings* settings) const {
    (void)settings;
    return "wchar16";
}

std::string WideChar16DataType::getRepresentation(MemBuffer* buf, Settings* settings,
                                                    int length) const {
    return StringDataInstance(const_cast<WideChar16DataType*>(this), settings, buf, getLength())
        .getCharRepresentation();
}

std::string WideChar16DataType::getDefaultLabelPrefix() const {
    return "WCHAR16";
}

std::string WideChar16DataType::getDefaultLabelPrefix(MemBuffer* buf, Settings* settings,
                                                        int length,
                                                        DataTypeDisplayOptions* options) const {
    (void)length; (void)options;
    std::string str = "WCHAR16_";
    if (buf == nullptr) return str + "??";
    try {
        int val = buf->getUnsignedShort(0);
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

std::vector<SettingsDefinition*> WideChar16DataType::getSettingsDefinitions() const {
    return {
        const_cast<EndianSettingsDefinition*>(&EndianSettingsDefinition::def()),
        const_cast<RenderUnicodeSettingsDefinition*>(&RenderUnicodeSettingsDefinition::def()),
        const_cast<TranslationSettingsDefinition*>(&TranslationSettingsDefinition::def())
    };
}

const std::type_info& WideChar16DataType::getValueClass(Settings* settings) const {
    (void)settings;
    return typeid(char);
}

std::vector<uint8_t> WideChar16DataType::encodeValue(void* value, MemBuffer* buf,
                                                       Settings* settings, int length) const {
    (void)value; (void)buf; (void)settings; (void)length;
    return {};
}

std::vector<uint8_t> WideChar16DataType::encodeRepresentation(const std::string& repr,
                                                               MemBuffer* buf, Settings* settings,
                                                               int length) const {
    (void)repr; (void)buf; (void)settings; (void)length;
    return {};
}

std::string WideChar16DataType::getCharsetName(Settings* settings) const {
    (void)settings;
    return CharsetInfoManager::UTF16;
}

bool WideChar16DataType::hasStringValue(Settings* settings) const {
    (void)settings;
    return true;
}

std::string WideChar16DataType::getArrayDefaultLabelPrefix(MemBuffer* buf, Settings* settings,
                                                             int len,
                                                             const DataTypeDisplayOptions& options) const {
    return StringDataInstance(const_cast<WideChar16DataType*>(this), settings, buf, len, true)
        .getLabel(AbstractStringDataType::DEFAULT_UNICODE_ABBREV_PREFIX + "_",
                  AbstractStringDataType::DEFAULT_UNICODE_LABEL_PREFIX,
                  AbstractStringDataType::DEFAULT_UNICODE_LABEL, options);
}

std::string WideChar16DataType::getArrayDefaultOffcutLabelPrefix(MemBuffer* buf, Settings* settings,
                                                                   int len,
                                                                   const DataTypeDisplayOptions* options,
                                                                   int offcutLength) const {
    return StringDataInstance(const_cast<WideChar16DataType*>(this), settings, buf, len, true)
        .getOffcutLabelString(AbstractStringDataType::DEFAULT_UNICODE_ABBREV_PREFIX + "_",
                              AbstractStringDataType::DEFAULT_UNICODE_LABEL_PREFIX,
                              AbstractStringDataType::DEFAULT_UNICODE_LABEL, *options,
                              offcutLength);
}

} // namespace ghidra
