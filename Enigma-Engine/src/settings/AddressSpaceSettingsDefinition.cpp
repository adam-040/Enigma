/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AddressSpaceSettingsDefinition.cpp
/// \brief Settings definition for address space name
#include <ghidra/AddressSpaceSettingsDefinition.h>
#include <ghidra/Settings.h>

namespace ghidra {

namespace {
    const char addrSpaceStorageKey[] = "addr_space_name";
    const char addrSpaceDescription[] = "Identifies the referenced address space name (case-sensitive; ignored if no match)";
    const char addrSpaceDisplayName[] = "Address Space";
}

AddressSpaceSettingsDefinition& AddressSpaceSettingsDefinition::def() {
    static AddressSpaceSettingsDefinition instance;
    return instance;
}

std::string AddressSpaceSettingsDefinition::getValue(const Settings* settings) const {
    if (settings == nullptr) {
        return "";
    }
    if (!settings->hasString(addrSpaceStorageKey)) {
        return "";
    }
    return settings->getString(addrSpaceStorageKey);
}

void AddressSpaceSettingsDefinition::setValue(Settings* settings, const std::string& value) {
    if (value.empty()) {
        settings->clearSetting(addrSpaceStorageKey);
    } else {
        settings->setString(addrSpaceStorageKey, value);
    }
}

bool AddressSpaceSettingsDefinition::hasValue(const Settings* settings) const {
    return !getValue(settings).empty();
}

void AddressSpaceSettingsDefinition::clear(Settings* settings) const {
    settings->clearSetting(addrSpaceStorageKey);
}

void AddressSpaceSettingsDefinition::copySetting(const Settings* srcSettings, Settings* destSettings) const {
    if (!srcSettings->hasString(addrSpaceStorageKey)) {
        destSettings->clearSetting(addrSpaceStorageKey);
    } else {
        destSettings->setString(addrSpaceStorageKey, srcSettings->getString(addrSpaceStorageKey));
    }
}

std::string AddressSpaceSettingsDefinition::getAttributeSpecification(const Settings* settings) const {
    std::string spaceName = getValue(settings);
    if (!spaceName.empty()) {
        return "space(" + spaceName + ")";
    }
    return "";
}

std::string AddressSpaceSettingsDefinition::getName() const { return addrSpaceDisplayName; }
std::string AddressSpaceSettingsDefinition::getStorageKey() const { return addrSpaceStorageKey; }
std::string AddressSpaceSettingsDefinition::getDescription() const { return addrSpaceDescription; }
bool AddressSpaceSettingsDefinition::supportsSuggestedValues() const { return true; }

} // namespace ghidra
