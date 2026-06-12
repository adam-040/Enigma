/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra\DefaultDataType.h>

namespace ghidra {

DefaultDataType& DefaultDataType::dataType() {
    static DefaultDataType instance;
    return instance;
}

DefaultDataType::DefaultDataType()
    : AbstractDataType(CategoryPath::ROOT(), "undefined", nullptr) {}

std::string DefaultDataType::getMnemonic(Settings* settings) const {
    return "??";
}

int DefaultDataType::getLength() const {
    return 1;
}

int DefaultDataType::getAlignedLength() const {
    return 1;
}

std::string DefaultDataType::getDescription() const {
    return "Undefined Byte";
}

std::string DefaultDataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    return "??";
}

const std::type_info& DefaultDataType::getValueClass(Settings* settings) const {
    return typeid(Scalar);
}

DataType* DefaultDataType::clone(DataTypeManager* dtm) const {
    return const_cast<DefaultDataType*>(this);
}

DataType* DefaultDataType::copy(DataTypeManager* dtm) const {
    return const_cast<DefaultDataType*>(this);
}

bool DefaultDataType::isEquivalent(const DataType* dt) const {
    return dt == this;
}

int DefaultDataType::getAlignment() const {
    return 1;
}

std::vector<SettingsDefinition*> DefaultDataType::getSettingsDefinitions() const {
    return {};
}

Settings* DefaultDataType::getDefaultSettings() const {
    return nullptr;
}

void DefaultDataType::addParent(DataType* dt) {
}

void DefaultDataType::removeParent(DataType* dt) {
}

int64_t DefaultDataType::getLastChangeTime() const {
    return NO_SOURCE_SYNC_TIME;
}

} // namespace ghidra
