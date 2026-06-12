/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file NumberSettingsDefinition.cpp
/// \brief Interface for SettingsDefinitions that have numeric (long) values
#include <ghidra/NumberSettingsDefinition.h>

namespace ghidra {

std::string NumberSettingsDefinition::getValueString(const Settings* settings) const {
    int64_t value = getValue(settings);
    if (!allowNegativeValue()) {
        uint64_t unsignedValue = static_cast<uint64_t>(value);
        std::ostringstream oss;
        oss << "0x" << std::hex << unsignedValue;
        return oss.str();
    }
    if (value < 0) {
        std::ostringstream oss;
        oss << "-0x" << std::hex << static_cast<uint64_t>(-value);
        return oss.str();
    }
    std::ostringstream oss;
    oss << "0x" << std::hex << static_cast<uint64_t>(value);
    return oss.str();
}

bool NumberSettingsDefinition::hasSameValue(const Settings* settings1, const Settings* settings2) const {
    return getValue(settings1) == getValue(settings2);
}

} // namespace ghidra
