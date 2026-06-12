/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file NoSettings.h
/// \brief A no-op Settings implementation used as a default for null settings.
/// Translated from: ghidra.program.model.data.SettingsImpl.NO_SETTINGS
#pragma once

#include "Settings.h"
#include <string>
#include <vector>
#include <cstdint>

namespace ghidra {

/**
 * A read-only no-op Settings implementation used as a default when callers
 * pass a nullptr Settings.  All get* methods return defaults (0, empty
 * string, nullptr); all set* methods are no-ops.
 *
 * Translated from: ghidra.program.model.data.SettingsImpl.NO_SETTINGS
 */
class NoSettings : public Settings {
public:
    static NoSettings& instance();

    bool isImmutableSettings() const override { return true; }
    bool isChangeAllowed(const SettingsDefinition* def) const override { return false; }

    int64_t getLong(const std::string& name) const override;
    bool hasLong(const std::string& name) const override;

    std::string getString(const std::string& name) const override;
    bool hasString(const std::string& name) const override;

    void* getValue(const std::string& name) const override;

    void setLong(const std::string& name, int64_t value) override;
    void setString(const std::string& name, const std::string& value) override;
    void setValue(const std::string& name, void* value) override;

    void clearSetting(const std::string& name) override;
    void clearAllSettings() override;

    std::vector<std::string> getNames() const override;
    bool isEmpty() const override;

    Settings* getDefaultSettings() const override;
    void setDefaultSettings(Settings* settings) override;
};

} // namespace ghidra
