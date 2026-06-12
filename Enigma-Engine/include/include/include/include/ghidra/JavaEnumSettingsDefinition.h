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
/// \file JavaEnumSettingsDefinition.h
/// \brief A SettingsDefinition implementation that uses a real C++ enum
/// Translated from: ghidra.docking.settings.JavaEnumSettingsDefinition
#pragma once

#include <string>
#include <vector>
#include <algorithm>
#include "ghidra/EnumSettingsDefinition.h"
#include "ghidra/Settings.h"

namespace ghidra {

/**
 * A SettingsDefinition implementation that uses a real C++ enum.
 * T must be an enum class or enum with contiguous values starting at 0.
 */
template<typename T>
class JavaEnumSettingsDefinition : public EnumSettingsDefinition {
private:
    std::string name_;
    std::string settingName_;
    std::string description_;
    std::vector<std::string> valueNames_;
    T defaultValue_;
    int valueCount_;

public:
    JavaEnumSettingsDefinition(const std::string& settingName, const std::string& name,
                               const std::string& description, T defaultValue, int valueCount)
        : name_(name), settingName_(settingName), description_(description),
          defaultValue_(defaultValue), valueCount_(valueCount)
    {
    }

    /// Returns the Enum instance that is the default Enum for this SettingsDefinition
    T getDefaultEnum() const { return defaultValue_; }

    /// Returns an enum instance that corresponds to the setting stored, or the default
    T getEnumValue(const Settings* settings) const {
        return getEnumValue(settings, defaultValue_);
    }

    /// Returns an enum instance that corresponds to the setting stored, or a custom default
    T getEnumValue(const Settings* settings, T defaultValueOverride) const {
        if (!settings || !settings->hasLong(settingName_)) {
            return defaultValueOverride;
        }
        int valueOrdinal = static_cast<int>(settings->getLong(settingName_));
        if (valueOrdinal >= 0 && valueOrdinal < valueCount_) {
            return static_cast<T>(valueOrdinal);
        }
        return defaultValueOverride;
    }

    /// Sets the value of this SettingsDefinition using the ordinal of the specified enum
    void setEnumValue(Settings* settings, T enumValue) {
        setChoice(settings, static_cast<int>(enumValue));
    }

    /// Returns the Enum instance that corresponds to the specified ordinal value
    T getEnumByOrdinal(int ordinal) const {
        return static_cast<T>(ordinal);
    }

    /// Returns the Enum's ordinal using the Enum's string representation
    int getOrdinalByString(const std::string& stringValue) const {
        for (int i = 0; i < static_cast<int>(valueNames_.size()); i++) {
            if (valueNames_[i] == stringValue) {
                return i;
            }
        }
        return -1;
    }

    bool hasValue(const Settings* setting) const override {
        return setting->hasLong(settingName_);
    }

    std::string getName() const override { return name_; }

    std::string getStorageKey() const override { return settingName_; }

    std::string getDescription() const override { return description_; }

    void clear(Settings* settings) const override {
        settings->clearSetting(settingName_);
    }

    void copySetting(const Settings* srcSettings, Settings* destSettings) const override {
        if (!srcSettings->hasLong(settingName_)) {
            destSettings->clearSetting(settingName_);
        } else {
            setChoiceValue(destSettings, static_cast<int>(srcSettings->getLong(settingName_)));
        }
    }

    int getChoice(const Settings* settings) const override {
        if (!settings || !settings->hasLong(settingName_)) {
            return static_cast<int>(defaultValue_);
        }
        int value = static_cast<int>(settings->getLong(settingName_));
        return std::min(std::max(value, 0), valueCount_ - 1);
    }

    std::string getValueString(const Settings* settings) const override {
        return valueNames_[getChoice(settings)];
    }

    void setChoice(Settings* settings, int value) override {
        settings->setLong(settingName_, value);
    }

    std::string getDisplayChoice(int value, const Settings* settings) const override {
        (void)settings;
        return valueNames_[value];
    }

    std::vector<std::string> getDisplayChoices(const Settings* settings) const override {
        (void)settings;
        return valueNames_;
    }

    void setValueNames(std::vector<std::string> names) {
        valueNames_ = std::move(names);
    }

protected:
    void setChoiceValue(Settings* settings, int value) const {
        settings->setLong(settingName_, value);
    }
};

} // namespace ghidra
