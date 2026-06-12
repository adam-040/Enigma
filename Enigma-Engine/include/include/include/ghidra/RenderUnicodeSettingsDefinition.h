/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file RenderUnicodeSettingsDefinition.h
/// \brief Settings definition for controlling the display of UNICODE characters.
/// Translated from: ghidra.program.model.data.RenderUnicodeSettingsDefinition
#pragma once

#include "JavaEnumSettingsDefinition.h"
#include <string>
#include <vector>

namespace ghidra {

/**
 * Settings definition for controlling the display of UNICODE characters.
 *
 * Translated from: ghidra.program.model.data.RenderUnicodeSettingsDefinition
 */
enum class RenderUnicodeEnum {
    ALL,
    BYTE_SEQ,
    ESC_SEQ
};

class RenderUnicodeSettingsDefinition
    : public JavaEnumSettingsDefinition<RenderUnicodeEnum> {
public:
    static const int VALUE_COUNT = 3;

    static RenderUnicodeSettingsDefinition& def();
    static RenderUnicodeSettingsDefinition& RENDER();

    bool isRenderAlphanumericOnly(const Settings* settings) const;

private:
    static const std::string SETTING_NAME;
    static const std::string DISPLAY_NAME;
    static const std::string DESCRIPTION;

    RenderUnicodeSettingsDefinition();
};

} // namespace ghidra
