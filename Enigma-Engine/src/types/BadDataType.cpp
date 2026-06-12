/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/BadDataType.h>

namespace ghidra {

BadDataType BadDataType::dataType;

BadDataType::BadDataType()
    : BuiltIn(CategoryPath::ROOT(), "-BAD-", nullptr) {}

DataType* BadDataType::clone(DataTypeManager* dtm) const {
    return const_cast<BadDataType*>(this);
}

std::string BadDataType::getMnemonic(Settings* settings) const {
    return getName();
}

int BadDataType::getLength() const {
    return -1;
}

std::string BadDataType::getDescription() const {
    return "** Bad Data Type **";
}

bool BadDataType::isEquivalent(const DataType* dt) const {
    return dynamic_cast<const BadDataType*>(dt) != nullptr;
}

std::string BadDataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    return getDescription();
}

bool BadDataType::canSpecifyLength() {
    return true;
}

int BadDataType::getLength(MemBuffer* buf, int maxLength) {
    return -1;
}

DataType* BadDataType::getReplacementBaseType() {
    return nullptr;
}

std::string BadDataType::getCTypeDeclaration(DataOrganization* dataOrganization) {
    return "";
}

void BadDataType::setDefaultSettings(Settings* settings) {}

} // namespace ghidra
