/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file TranslationSettingsDefinition.h
/// \brief SettingsDefinition for translation display.
/// Translated from: ghidra.program.model.data.TranslationSettingsDefinition
#pragma once

#include "JavaEnumSettingsDefinition.h"
#include <string>

namespace ghidra {

/**
 * SettingsDefinition for translation display (show original vs show translated).
 * The property-map helpers (hasTranslatedValue, getTranslatedValue,
 * setTranslatedValue) are not ported here because PropertyMapManager and
 * StringPropertyMap are not yet ported.
 *
 * Translated from: ghidra.program.model.data.TranslationSettingsDefinition
 */
enum class TranslationEnum {
    SHOW_ORIGINAL,
    SHOW_TRANSLATED
};

class TranslationSettingsDefinition
    : public JavaEnumSettingsDefinition<TranslationEnum> {
public:
    static const int VALUE_COUNT = 2;

    static TranslationSettingsDefinition& def();
    static TranslationSettingsDefinition& TRANSLATION();

    static TranslationEnum invert(TranslationEnum v) {
        return v == TranslationEnum::SHOW_ORIGINAL ? TranslationEnum::SHOW_TRANSLATED
                                                   : TranslationEnum::SHOW_ORIGINAL;
    }

    bool isShowTranslated(const Settings* settings) const;
    void setShowTranslated(Settings* settings, bool shouldShowTranslatedValue);

private:
    static const std::string SETTING_NAME;
    static const std::string DISPLAY_NAME;
    static const std::string DESCRIPTION;
    static const std::string TRANSLATION_PROPERTY_MAP_NAME;
    static const std::string DEPRECATED_TRANSLATED_VALUE_SETTING_NAME;

    TranslationSettingsDefinition();
};

} // namespace ghidra
