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
/// \file Settings.h
/// \brief Interface for storing name-value pairs used by DataType display options
/// Translated from: ghidra.docking.settings.Settings
#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace ghidra {

class SettingsDefinition;
class StringSettingsDefinition;

/**
 * Settings objects store name-value pairs. Each SettingsDefinition defines one
 * or more names to use to store values in settings objects. Exactly what type
 * of value and how to interpret the value is done by the SettingsDefinition object.
 */
class Settings {
public:
    virtual ~Settings() = default;

    /// Returns true if settings may not be modified
    virtual bool isImmutableSettings() const = 0;

    /// Determine if a settings change corresponding to the specified settingsDefinition is permitted
    virtual bool isChangeAllowed(const SettingsDefinition* settingsDefinition) const = 0;

    /// Gets the Long value associated with the given name
    virtual int64_t getLong(const std::string& name) const = 0;

    /// Returns true if a long value exists for the given name
    virtual bool hasLong(const std::string& name) const = 0;

    /// Gets the String value associated with the given name
    virtual std::string getString(const std::string& name) const = 0;

    /// Returns true if a string value exists for the given name
    virtual bool hasString(const std::string& name) const = 0;

    /// Gets the object associated with the given name
    virtual void* getValue(const std::string& name) const = 0;

    /// Associates the given long value with the name
    virtual void setLong(const std::string& name, int64_t value) = 0;

    /// Associates the given String value with the name
    virtual void setString(const std::string& name, const std::string& value) = 0;

    /// Associates the given object with the name
    virtual void setValue(const std::string& name, void* value) = 0;

    /// Removes any value associated with the given name
    virtual void clearSetting(const std::string& name) = 0;

    /// Removes all name-value pairs from this settings object
    virtual void clearAllSettings() = 0;

    /// Get the list of keys that currently have values associated with them
    virtual std::vector<std::string> getNames() const = 0;

    /// Returns true if there are no key-value pairs stored in this settings object
    virtual bool isEmpty() const = 0;

    /// Returns the underlying default settings or nullptr if there are none
    virtual Settings* getDefaultSettings() const = 0;

    /// Sets the underlying default settings
    virtual void setDefaultSettings(Settings* settings) = 0;
};

} // namespace ghidra
