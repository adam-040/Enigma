/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file NoSettings.cpp
#include "ghidra/NoSettings.h"

namespace ghidra {

NoSettings& NoSettings::instance() {
    static NoSettings inst;
    return inst;
}

int64_t NoSettings::getLong(const std::string& name) const { (void)name; return 0; }
bool NoSettings::hasLong(const std::string& name) const { (void)name; return false; }
std::string NoSettings::getString(const std::string& name) const { (void)name; return std::string(); }
bool NoSettings::hasString(const std::string& name) const { (void)name; return false; }
void* NoSettings::getValue(const std::string& name) const { (void)name; return nullptr; }

void NoSettings::setLong(const std::string& name, int64_t value) { (void)name; (void)value; }
void NoSettings::setString(const std::string& name, const std::string& value) { (void)name; (void)value; }
void NoSettings::setValue(const std::string& name, void* value) { (void)name; (void)value; }
void NoSettings::clearSetting(const std::string& name) { (void)name; }
void NoSettings::clearAllSettings() {}

std::vector<std::string> NoSettings::getNames() const { return {}; }
bool NoSettings::isEmpty() const { return true; }
Settings* NoSettings::getDefaultSettings() const { return nullptr; }
void NoSettings::setDefaultSettings(Settings* settings) { (void)settings; }

} // namespace ghidra
