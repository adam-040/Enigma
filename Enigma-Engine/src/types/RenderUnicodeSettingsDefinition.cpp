/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file RenderUnicodeSettingsDefinition.cpp
#include "ghidra/RenderUnicodeSettingsDefinition.h"

namespace ghidra {

const std::string RenderUnicodeSettingsDefinition::SETTING_NAME = "renderUnicode";
const std::string RenderUnicodeSettingsDefinition::DISPLAY_NAME = "Render non-ASCII Unicode";
const std::string RenderUnicodeSettingsDefinition::DESCRIPTION =
    "Selects if the unicode string should render all characters or only alphanumeric characters";

RenderUnicodeSettingsDefinition::RenderUnicodeSettingsDefinition()
    : JavaEnumSettingsDefinition<RenderUnicodeEnum>(SETTING_NAME, DISPLAY_NAME, DESCRIPTION,
                                                    RenderUnicodeEnum::ALL, VALUE_COUNT) {
    setValueNames({"all", "byte sequence", "escape sequence"});
}

RenderUnicodeSettingsDefinition& RenderUnicodeSettingsDefinition::def() {
    static RenderUnicodeSettingsDefinition instance;
    return instance;
}

RenderUnicodeSettingsDefinition& RenderUnicodeSettingsDefinition::RENDER() {
    return def();
}

bool RenderUnicodeSettingsDefinition::isRenderAlphanumericOnly(const Settings* settings) const {
    return getEnumValue(settings) == RenderUnicodeEnum::BYTE_SEQ;
}

} // namespace ghidra
