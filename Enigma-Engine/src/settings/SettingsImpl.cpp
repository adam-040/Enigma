/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SettingsImpl.cpp
/// \brief Basic implementation of the Settings interface
#include <ghidra/SettingsImpl.h>
#include <ghidra/Settings.h>

namespace ghidra {

bool SettingsImpl::checkSetting(const std::string& type, const std::string& name) const {
    if (!checkImmutableSetting(type, name)) return false;
    if (!name.empty() && allowedSettingPredicate_ && !allowedSettingPredicate_(name)) {
        return false;
    }
    return true;
}

bool SettingsImpl::checkImmutableSetting(const std::string& type, const std::string& name) const {
    if (immutable_) return false;
    (void)type; (void)name;
    return true;
}

SettingsImpl::SettingsImpl()
    : defaultSettings_(nullptr), immutable_(false) {}

SettingsImpl::SettingsImpl(std::function<bool(const std::string&)> allowedSettingPredicate)
    : defaultSettings_(nullptr), immutable_(false),
      allowedSettingPredicate_(std::move(allowedSettingPredicate)) {}

SettingsImpl::SettingsImpl(const Settings* settings)
    : defaultSettings_(nullptr), immutable_(false)
{
    if (settings) {
        for (const auto& name : settings->getNames()) {
            void* val = settings->getValue(name);
            if (val) {
                objectValues_[name] = val;
            }
        }
        defaultSettings_ = settings->getDefaultSettings();
    }
}

SettingsImpl::SettingsImpl(bool immutable)
    : defaultSettings_(nullptr), immutable_(immutable) {}

bool SettingsImpl::isImmutableSettings() const { return immutable_; }

bool SettingsImpl::isChangeAllowed(const SettingsDefinition* settingsDefinition) const {
    if (immutable_) return false;
    if (allowedSettingPredicate_ && settingsDefinition) {
        return allowedSettingPredicate_(settingsDefinition->getStorageKey());
    }
    return true;
}

bool SettingsImpl::isEmpty() const {
    return longValues_.empty() && stringValues_.empty() && objectValues_.empty();
}

int64_t SettingsImpl::getLong(const std::string& name) const {
    auto it = longValues_.find(name);
    if (it != longValues_.end()) return it->second;
    if (defaultSettings_) return defaultSettings_->getLong(name);
    return 0;
}

bool SettingsImpl::hasLong(const std::string& name) const {
    return longValues_.find(name) != longValues_.end();
}

std::string SettingsImpl::getString(const std::string& name) const {
    auto it = stringValues_.find(name);
    if (it != stringValues_.end()) return it->second;
    if (defaultSettings_) return defaultSettings_->getString(name);
    return "";
}

bool SettingsImpl::hasString(const std::string& name) const {
    return stringValues_.find(name) != stringValues_.end();
}

void* SettingsImpl::getValue(const std::string& name) const {
    auto it = objectValues_.find(name);
    if (it != objectValues_.end()) return it->second;
    auto sit = stringValues_.find(name);
    if (sit != stringValues_.end()) return const_cast<char*>(sit->second.c_str());
    if (defaultSettings_) return defaultSettings_->getValue(name);
    return nullptr;
}

void SettingsImpl::setLong(const std::string& name, int64_t value) {
    if (checkSetting("long", name)) {
        longValues_[name] = value;
    }
}

void SettingsImpl::setString(const std::string& name, const std::string& value) {
    if (checkSetting("string", name)) {
        stringValues_[name] = value;
    }
}

void SettingsImpl::setValue(const std::string& name, void* value) {
    if (checkSetting("object", name)) {
        objectValues_[name] = value;
    }
}

void SettingsImpl::clearSetting(const std::string& name) {
    if (checkImmutableSetting("", name)) {
        longValues_.erase(name);
        stringValues_.erase(name);
        objectValues_.erase(name);
    }
}

void SettingsImpl::clearAllSettings() {
    if (checkImmutableSetting("", "")) {
        longValues_.clear();
        stringValues_.clear();
        objectValues_.clear();
    }
}

std::vector<std::string> SettingsImpl::getNames() const {
    std::vector<std::string> names;
    for (const auto& kv : longValues_) names.push_back(kv.first);
    for (const auto& kv : stringValues_) {
        bool found = false;
        for (const auto& n : longValues_) { if (n.first == kv.first) { found = true; break; } }
        if (!found) names.push_back(kv.first);
    }
    for (const auto& kv : objectValues_) {
        bool found = false;
        for (const auto& n : longValues_) { if (n.first == kv.first) { found = true; break; } }
        if (!found) {
            for (const auto& n : stringValues_) { if (n.first == kv.first) { found = true; break; } }
        }
        if (!found) names.push_back(kv.first);
    }
    return names;
}

Settings* SettingsImpl::getDefaultSettings() const { return defaultSettings_; }

void SettingsImpl::setDefaultSettings(Settings* settings) { defaultSettings_ = settings; }

} // namespace ghidra
