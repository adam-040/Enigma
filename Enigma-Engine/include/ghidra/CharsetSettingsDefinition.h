/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file CharsetSettingsDefinition.h
/// \brief SettingsDefinition for setting the charset of a string instance.
/// Translated from: ghidra.program.model.data.CharsetSettingsDefinition
#pragma once

#include "EnumSettingsDefinition.h"
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

namespace ghidra {

/**
 * SettingsDefinition for setting the charset of a string instance.
 *
 * The charset list is currently a hardcoded minimal set of standard charsets;
 * when CharsetInfoManager is ported this can be replaced with the live JVM
 * charset enumeration.
 *
 * Translated from: ghidra.program.model.data.CharsetSettingsDefinition
 */
class CharsetSettingsDefinition : public EnumSettingsDefinition {
public:
    static CharsetSettingsDefinition& def();
    static CharsetSettingsDefinition& CHARSET();

    std::string getCharset(const Settings* settings, const std::string& defaultValue) const;

    void setCharset(Settings* settings, const std::string& charset) const;

    std::string getValueString(const Settings* settings) const override;

    int getChoice(const Settings* settings) const override;

    void setChoice(Settings* settings, int ordinalOfValue) override;

    std::vector<std::string> getDisplayChoices(const Settings* settings) const override;

    std::string getName() const override;

    std::string getStorageKey() const override;

    std::string getDescription() const override;

    std::string getDisplayChoice(int ordinalOfValue, const Settings* settings) const override;

    void clear(Settings* settings) const override;

    void copySetting(const Settings* srcSettings, Settings* destSettings) const override;

    bool hasValue(const Settings* setting) const override;

    bool hasSameValue(const Settings* settings1, const Settings* settings2) const override;

    static void setStaticEncodingMappingValues(
        const std::unordered_map<int64_t, std::vector<std::string>>& mappingValues);

private:
    static const std::string CHARSET_SETTING_NAME;
    static const std::string DEPRECATED_ENCODING_SETTING_NAME;
    static const std::string DEPRECATED_LANGUAGE_SETTING_NAME;
    static const std::string CHARSET_NAME_DISPLAY;

    CharsetSettingsDefinition();

    std::vector<std::string> ordinalToString_;
    std::unordered_map<std::string, int> stringToOrdinal_;
    static std::unordered_map<int64_t, std::vector<std::string>> languageToCharsetIndexMap_;

    std::string getDeprecatedEncodingValue(const Settings* settings) const;
};

} // namespace ghidra
