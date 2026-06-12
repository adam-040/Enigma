/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file WideCharDataType.cpp
#include "ghidra/WideCharDataType.h"
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

namespace {
int getWideCharSizeDefault() {
    return 2;
}
} // namespace

WideCharDataType& WideCharDataType::dataType() {
    static WideCharDataType instance;
    return instance;
}

WideCharDataType::WideCharDataType(DataTypeManager* dtm)
    : BuiltIn(CategoryPath::ROOT(), "wchar_t", dtm) {}

DataType* WideCharDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<WideCharDataType*>(this);
    }
    return new WideCharDataType(dtm);
}

int WideCharDataType::getLength() const {
    return getWideCharSizeDefault();
}

std::string WideCharDataType::getDescription() const {
    return "Wide-Character (compiler-specific size)";
}

std::string WideCharDataType::getMnemonic(Settings* settings) const {
    (void)settings;
    return "wchar_t";
}

std::string WideCharDataType::getRepresentation(MemBuffer* buf, Settings* settings,
                                                  int length) const {
    return StringDataInstance(const_cast<WideCharDataType*>(this), settings, buf, getLength())
        .getCharRepresentation();
}

std::string WideCharDataType::getDefaultLabelPrefix() const {
    return "WCHAR";
}

std::string WideCharDataType::getDefaultLabelPrefix(MemBuffer* buf, Settings* settings,
                                                      int length,
                                                      DataTypeDisplayOptions* options) const {
    (void)length; (void)options;
    std::string str = "WCHAR_";
    if (buf == nullptr) return str + "??";
    try {
        int sz = getLength();
        int val = 0;
        if (sz == 2) val = buf->getUnsignedShort(0);
        else if (sz == 4) val = buf->getInt(0);
        else return str + "??";
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

std::vector<SettingsDefinition*> WideCharDataType::getSettingsDefinitions() const {
    return {
        const_cast<EndianSettingsDefinition*>(&EndianSettingsDefinition::def()),
        const_cast<RenderUnicodeSettingsDefinition*>(&RenderUnicodeSettingsDefinition::def()),
        const_cast<TranslationSettingsDefinition*>(&TranslationSettingsDefinition::def())
    };
}

const std::type_info& WideCharDataType::getValueClass(Settings* settings) const {
    (void)settings;
    int sz = getLength();
    if (sz == 2) return typeid(char);
    if (sz == 4) return typeid(int);
    return typeid(void);
}

std::vector<uint8_t> WideCharDataType::encodeValue(void* value, MemBuffer* buf,
                                                     Settings* settings, int length) const {
    (void)value; (void)buf; (void)settings; (void)length;
    return {};
}

std::vector<uint8_t> WideCharDataType::encodeRepresentation(const std::string& repr,
                                                             MemBuffer* buf, Settings* settings,
                                                             int length) const {
    (void)repr; (void)buf; (void)settings; (void)length;
    return {};
}

std::string WideCharDataType::getCharsetName(Settings* settings) const {
    (void)settings;
    int sz = getLength();
    if (sz == 2) return CharsetInfoManager::UTF16;
    if (sz == 4) return CharsetInfoManager::UTF32;
    return "US-ASCII";
}

bool WideCharDataType::hasStringValue(Settings* settings) const {
    (void)settings;
    return true;
}

std::string WideCharDataType::getArrayDefaultLabelPrefix(MemBuffer* buf, Settings* settings,
                                                           int len,
                                                           const DataTypeDisplayOptions& options) const {
    return StringDataInstance(const_cast<WideCharDataType*>(this), settings, buf, len, true)
        .getLabel(AbstractStringDataType::DEFAULT_UNICODE_ABBREV_PREFIX + "_",
                  AbstractStringDataType::DEFAULT_UNICODE_LABEL_PREFIX,
                  AbstractStringDataType::DEFAULT_UNICODE_LABEL, options);
}

std::string WideCharDataType::getArrayDefaultOffcutLabelPrefix(MemBuffer* buf, Settings* settings,
                                                                 int len,
                                                                 const DataTypeDisplayOptions& options,
                                                                 int offcutLength) const {
    return StringDataInstance(const_cast<WideCharDataType*>(this), settings, buf, len, true)
        .getOffcutLabelString(AbstractStringDataType::DEFAULT_UNICODE_ABBREV_PREFIX + "_",
                              AbstractStringDataType::DEFAULT_UNICODE_LABEL_PREFIX,
                              AbstractStringDataType::DEFAULT_UNICODE_LABEL, options,
                              offcutLength);
}

} // namespace ghidra
