/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra\VoidDataType.h>

namespace ghidra {

VoidDataType& VoidDataType::dataType() {
    static VoidDataType instance(nullptr);
    return instance;
}

VoidDataType::VoidDataType(DataTypeManager* dtm)
    : AbstractDataType(CategoryPath::ROOT(), "void", dtm) {}

std::string VoidDataType::getMnemonic(Settings* settings) const {
    return "void";
}

int VoidDataType::getLength() const {
    return 0;
}

int VoidDataType::getAlignedLength() const {
    return 0;
}

std::string VoidDataType::getDescription() const {
    return "void datatype";
}

std::string VoidDataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    return "";
}

const std::type_info& VoidDataType::getValueClass(Settings* settings) const {
    return typeid(void);
}

DataType* VoidDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<VoidDataType*>(this);
    }
    return new VoidDataType(dtm);
}

DataType* VoidDataType::copy(DataTypeManager* dtm) const {
    return new VoidDataType(dtm);
}

bool VoidDataType::isEquivalent(const DataType* dt) const {
    return dt && dynamic_cast<const VoidDataType*>(dt) != nullptr;
}

bool VoidDataType::isZeroLength() const {
    return true;
}

int VoidDataType::getAlignment() const {
    return 1;
}

std::vector<SettingsDefinition*> VoidDataType::getSettingsDefinitions() const {
    return {};
}

Settings* VoidDataType::getDefaultSettings() const {
    return nullptr;
}

bool VoidDataType::isVoidDataType(const DataType* dt) {
    if (!dt) return false;
    return dynamic_cast<const VoidDataType*>(dt) != nullptr;
}

} // namespace ghidra
