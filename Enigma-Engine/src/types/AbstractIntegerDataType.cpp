/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra\AbstractIntegerDataType.h>

namespace ghidra {

const std::string AbstractIntegerDataType::C_SIGNED_CHAR = "signed char";
const std::string AbstractIntegerDataType::C_UNSIGNED_CHAR = "unsigned char";
const std::string AbstractIntegerDataType::C_SIGNED_SHORT = "short";
const std::string AbstractIntegerDataType::C_UNSIGNED_SHORT = "unsigned short";
const std::string AbstractIntegerDataType::C_SIGNED_INT = "int";
const std::string AbstractIntegerDataType::C_UNSIGNED_INT = "unsigned int";
const std::string AbstractIntegerDataType::C_SIGNED_LONG = "long";
const std::string AbstractIntegerDataType::C_UNSIGNED_LONG = "unsigned long";
const std::string AbstractIntegerDataType::C_SIGNED_LONGLONG = "long long";
const std::string AbstractIntegerDataType::C_UNSIGNED_LONGLONG = "unsigned long long";

AbstractIntegerDataType::AbstractIntegerDataType(const std::string& name, DataTypeManager* dtm)
    : BuiltIn(CategoryPath::ROOT(), name, dtm) {}

AbstractIntegerDataType::~AbstractIntegerDataType() = default;

std::string AbstractIntegerDataType::getDefaultLabelPrefix() const {
    std::string upperName = name_;
    std::transform(upperName.begin(), upperName.end(), upperName.begin(), ::toupper);
    return upperName;
}

std::string AbstractIntegerDataType::getMnemonic(Settings* settings) const {
    return name_;
}

std::string AbstractIntegerDataType::getAssemblyMnemonic() const {
    return name_;
}

std::string AbstractIntegerDataType::getCMnemonic() const {
    std::string str = getCDeclaration();
    return !str.empty() ? str : name_;
}

std::string AbstractIntegerDataType::getCDeclaration() const {
    int size = getLength();
    if (size <= 0) {
        return "";
    }
    bool signedVal = isSigned();
    DataOrganization* dataOrganization = getDataOrganization();
    if (dataOrganization) {
        if (size == dataOrganization->getCharSize()) {
            return signedVal ? C_SIGNED_CHAR : C_UNSIGNED_CHAR;
        }
        if (size == dataOrganization->getIntegerSize()) {
            return signedVal ? C_SIGNED_INT : C_UNSIGNED_INT;
        }
        if (size == dataOrganization->getShortSize()) {
            return signedVal ? C_SIGNED_SHORT : C_UNSIGNED_SHORT;
        }
        if (size == dataOrganization->getLongSize()) {
            return signedVal ? C_SIGNED_LONG : C_UNSIGNED_LONG;
        }
        if (size == dataOrganization->getLongLongSize()) {
            return signedVal ? C_SIGNED_LONGLONG : C_UNSIGNED_LONGLONG;
        }
    } else {
        if (size == 1) return signedVal ? C_SIGNED_CHAR : C_UNSIGNED_CHAR;
        if (size == 2) return signedVal ? C_SIGNED_SHORT : C_UNSIGNED_SHORT;
        if (size == 4) return signedVal ? C_SIGNED_INT : C_UNSIGNED_INT;
        if (size == 8) return signedVal ? C_SIGNED_LONGLONG : C_UNSIGNED_LONGLONG;
    }
    return "";
}

std::string AbstractIntegerDataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    return "??";
}

const std::type_info& AbstractIntegerDataType::getValueClass(Settings* settings) const {
    return typeid(int64_t);
}

bool AbstractIntegerDataType::isEquivalent(const DataType* dt) const {
    if (!dt) return false;
    return typeid(*this) == typeid(*dt);
}

} // namespace ghidra
