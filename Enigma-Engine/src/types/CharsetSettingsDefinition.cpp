/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file CharsetSettingsDefinition.cpp
#include "ghidra/CharsetSettingsDefinition.h"
#include "ghidra/Settings.h"
#include <cstdint>

namespace ghidra {

const std::string CharsetSettingsDefinition::CHARSET_SETTING_NAME = "charset";
const std::string CharsetSettingsDefinition::DEPRECATED_ENCODING_SETTING_NAME = "encoding";
const std::string CharsetSettingsDefinition::DEPRECATED_LANGUAGE_SETTING_NAME = "language";
const std::string CharsetSettingsDefinition::CHARSET_NAME_DISPLAY = "Charset";

std::unordered_map<int64_t, std::vector<std::string>>
    CharsetSettingsDefinition::languageToCharsetIndexMap_;

CharsetSettingsDefinition::CharsetSettingsDefinition() {
    ordinalToString_ = {
        "US-ASCII",
        "UTF-8",
        "UTF-16",
        "UTF-16BE",
        "UTF-16LE",
        "UTF-32",
        "UTF-32BE",
        "UTF-32LE",
        "ISO-8859-1"
    };
    for (size_t i = 0; i < ordinalToString_.size(); ++i) {
        stringToOrdinal_[ordinalToString_[i]] = static_cast<int>(i);
    }
}

CharsetSettingsDefinition& CharsetSettingsDefinition::def() {
    static CharsetSettingsDefinition instance;
    return instance;
}

CharsetSettingsDefinition& CharsetSettingsDefinition::CHARSET() {
    return def();
}

std::string CharsetSettingsDefinition::getCharset(const Settings* settings,
                                                  const std::string& defaultValue) const {
    if (settings == nullptr) {
        return defaultValue;
    }
    std::string cs = settings->getString(CHARSET_SETTING_NAME);
    if (cs.empty()) {
        cs = getDeprecatedEncodingValue(settings);
    }
    return cs.empty() ? defaultValue : cs;
}

std::string CharsetSettingsDefinition::getValueString(const Settings* settings) const {
    return getCharset(settings, std::string());
}

std::string CharsetSettingsDefinition::getDeprecatedEncodingValue(const Settings* settings) const {
    if (settings == nullptr) {
        return std::string();
    }
    int64_t langIndex = settings->getLong(DEPRECATED_LANGUAGE_SETTING_NAME);
    int64_t encodingIndex = settings->getLong(DEPRECATED_ENCODING_SETTING_NAME);
    if (langIndex == 0 && encodingIndex == 0) {
        return std::string();
    }
    auto it = languageToCharsetIndexMap_.find(langIndex);
    if (it == languageToCharsetIndexMap_.end()) {
        return std::string();
    }
    const std::vector<std::string>& encodings = it->second;
    if (encodingIndex < 0 || encodingIndex >= static_cast<int64_t>(encodings.size())) {
        return std::string();
    }
    return encodings[static_cast<size_t>(encodingIndex)];
}

void CharsetSettingsDefinition::setCharset(Settings* settings, const std::string& charset) const {
    if (settings == nullptr) {
        return;
    }
    if (charset.empty()) {
        settings->clearSetting(CHARSET_SETTING_NAME);
    } else {
        settings->setString(CHARSET_SETTING_NAME, charset);
    }
    settings->clearSetting(DEPRECATED_ENCODING_SETTING_NAME);
    settings->clearSetting(DEPRECATED_LANGUAGE_SETTING_NAME);
}

int CharsetSettingsDefinition::getChoice(const Settings* settings) const {
    std::string cs = getCharset(settings, std::string());
    auto it = stringToOrdinal_.find(cs);
    return (it != stringToOrdinal_.end()) ? it->second : 0;
}

void CharsetSettingsDefinition::setChoice(Settings* settings, int ordinalOfValue) {
    if (settings == nullptr) {
        return;
    }
    if (ordinalOfValue < 0 ||
        static_cast<size_t>(ordinalOfValue) >= ordinalToString_.size()) {
        settings->clearSetting(CHARSET_SETTING_NAME);
    } else {
        settings->setString(CHARSET_SETTING_NAME,
                            ordinalToString_[static_cast<size_t>(ordinalOfValue)]);
    }
    settings->clearSetting(DEPRECATED_ENCODING_SETTING_NAME);
    settings->clearSetting(DEPRECATED_LANGUAGE_SETTING_NAME);
}

std::vector<std::string> CharsetSettingsDefinition::getDisplayChoices(
    const Settings* settings) const {
    return ordinalToString_;
}

std::string CharsetSettingsDefinition::getName() const {
    return CHARSET_NAME_DISPLAY;
}

std::string CharsetSettingsDefinition::getStorageKey() const {
    return CHARSET_SETTING_NAME;
}

std::string CharsetSettingsDefinition::getDescription() const {
    return "Character set";
}

std::string CharsetSettingsDefinition::getDisplayChoice(int ordinalOfValue,
                                                        const Settings* settings) const {
    if (ordinalOfValue < 0 ||
        static_cast<size_t>(ordinalOfValue) >= ordinalToString_.size()) {
        return std::string();
    }
    return ordinalToString_[static_cast<size_t>(ordinalOfValue)];
}

void CharsetSettingsDefinition::clear(Settings* settings) const {
    if (settings != nullptr) {
        settings->clearSetting(CHARSET_SETTING_NAME);
    }
}

void CharsetSettingsDefinition::copySetting(const Settings* srcSettings,
                                            Settings* destSettings) const {
    if (srcSettings == nullptr || destSettings == nullptr) {
        return;
    }
    std::string s = srcSettings->getString(CHARSET_SETTING_NAME);
    if (s.empty()) {
        destSettings->clearSetting(CHARSET_SETTING_NAME);
    } else {
        destSettings->setString(CHARSET_SETTING_NAME, s);
    }
}

bool CharsetSettingsDefinition::hasValue(const Settings* setting) const {
    if (setting == nullptr) {
        return false;
    }
    return setting->getValue(CHARSET_SETTING_NAME) != nullptr ||
           setting->getValue(DEPRECATED_ENCODING_SETTING_NAME) != nullptr;
}

bool CharsetSettingsDefinition::hasSameValue(const Settings* settings1,
                                             const Settings* settings2) const {
    return getCharset(settings1, std::string()) == getCharset(settings2, std::string());
}

void CharsetSettingsDefinition::setStaticEncodingMappingValues(
    const std::unordered_map<int64_t, std::vector<std::string>>& mappingValues) {
    languageToCharsetIndexMap_.clear();
    languageToCharsetIndexMap_ = mappingValues;
}

} // namespace ghidra
