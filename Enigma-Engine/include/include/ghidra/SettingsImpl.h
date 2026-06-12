/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/// \file SettingsImpl.h
/// \brief Basic implementation of the Settings interface
/// Translated from: ghidra.docking.settings.SettingsImpl
#pragma once

#include "ghidra/Settings.h"
#include "ghidra/SettingsDefinition.h"
#include <unordered_map>
#include <functional>
#include <stdexcept>

namespace ghidra {

/**
 * Basic implementation of the Settings object.
 * Stores name-value pairs with support for defaults, immutability,
 * and optional change predicates.
 */
class SettingsImpl : public Settings {
private:
    std::unordered_map<std::string, int64_t> longValues_;
    std::unordered_map<std::string, std::string> stringValues_;
    std::unordered_map<std::string, void*> objectValues_;
    Settings* defaultSettings_;
    bool immutable_;
    std::function<bool(const std::string&)> allowedSettingPredicate_;

    bool checkSetting(const std::string& type, const std::string& name) const;
    bool checkImmutableSetting(const std::string& type, const std::string& name) const;

public:
    /// Construct an empty mutable SettingsImpl
    SettingsImpl();

    /// Construct with a modification predicate
    explicit SettingsImpl(std::function<bool(const std::string&)> allowedSettingPredicate);

    /// Construct by copying another Settings object (values and defaults)
    explicit SettingsImpl(const Settings* settings);

    /// Construct with immutability flag
    explicit SettingsImpl(bool immutable);

    bool isImmutableSettings() const override;

    bool isChangeAllowed(const SettingsDefinition* settingsDefinition) const override;

    bool isEmpty() const override;

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

    Settings* getDefaultSettings() const override;

    void setDefaultSettings(Settings* settings) override;
};

} // namespace ghidra
