/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file TranslationSettingsDefinition.cpp
#include "ghidra/TranslationSettingsDefinition.h"

namespace ghidra {

const std::string TranslationSettingsDefinition::SETTING_NAME = "translated";
const std::string TranslationSettingsDefinition::DISPLAY_NAME = "Translation";
const std::string TranslationSettingsDefinition::DESCRIPTION =
    "Selects the display of translated strings";
const std::string TranslationSettingsDefinition::TRANSLATION_PROPERTY_MAP_NAME =
    "StringTranslations";
const std::string TranslationSettingsDefinition::DEPRECATED_TRANSLATED_VALUE_SETTING_NAME =
    "translation";

TranslationSettingsDefinition::TranslationSettingsDefinition()
    : JavaEnumSettingsDefinition<TranslationEnum>(SETTING_NAME, DISPLAY_NAME, DESCRIPTION,
                                                    TranslationEnum::SHOW_ORIGINAL, VALUE_COUNT) {
    setValueNames({"show original", "show translated"});
}

TranslationSettingsDefinition& TranslationSettingsDefinition::def() {
    static TranslationSettingsDefinition instance;
    return instance;
}

TranslationSettingsDefinition& TranslationSettingsDefinition::TRANSLATION() {
    return def();
}

bool TranslationSettingsDefinition::isShowTranslated(const Settings* settings) const {
    return getEnumValue(settings) == TranslationEnum::SHOW_TRANSLATED;
}

void TranslationSettingsDefinition::setShowTranslated(Settings* settings,
                                                       bool shouldShowTranslatedValue) {
    setEnumValue(settings, shouldShowTranslatedValue ? TranslationEnum::SHOW_TRANSLATED
                                                     : TranslationEnum::SHOW_ORIGINAL);
}

} // namespace ghidra
