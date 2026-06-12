/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file BuiltIn.cpp
/// \brief Base class for BuiltIn DataTypes implementation
#include "ghidra/BuiltIn.h"
#include <typeinfo>

namespace ghidra {

BuiltIn::BuiltIn(const CategoryPath& path, const std::string& name, DataTypeManager* dataMgr)
    : DataTypeImpl(path.isRoot() ? CategoryPath::ROOT() : path, name, dataMgr) {
}

BuiltIn::~BuiltIn() = default;

DataType* BuiltIn::copy(DataTypeManager* dtm) const {
    return clone(dtm);
}

std::vector<SettingsDefinition*> BuiltIn::getSettingsDefinitions() const {
    return {};
}

void BuiltIn::setDefaultSettings(Settings* settings) {
    defaultSettings_ = settings;
}

bool BuiltIn::isEquivalent(const DataType* dt) const {
    if (this == dt) return true;
    if (!dt) return false;
    return typeid(*this) == typeid(*dt);
}

int64_t BuiltIn::getLastChangeTime() const {
    return 0;
}

std::string BuiltIn::getDecompilerDisplayName() const {
    return name_;
}

std::string BuiltIn::getCTypeDeclaration(DataOrganization* dataOrganization) const {
    return getDecompilerDisplayName();
}

} // namespace ghidra
