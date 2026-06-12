/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AbstractFloatDataType.cpp
/// \brief Abstract float data type implementation
#include "ghidra/AbstractFloatDataType.h"
#include <algorithm>
#include <cctype>

namespace ghidra {

AbstractFloatDataType::AbstractFloatDataType(const std::string& name, int encodedLength, DataTypeManager* dtm)
    : BuiltIn(CategoryPath::ROOT(), name, dtm), encodedLength_(encodedLength) {
    if (encodedLength < 1) {
        throw std::invalid_argument("Invalid encoded length: " + std::to_string(encodedLength));
    }
    description_ = buildDescription();
}

AbstractFloatDataType::~AbstractFloatDataType() = default;

std::string AbstractFloatDataType::buildIEEE754StandardDescription() const {
    return "IEEE 754 floating-point type (" + std::to_string(encodedLength_ * 8) + 
           "-bit / " + std::to_string(encodedLength_) + "-byte format, aligned-length is " + 
           std::to_string(getAlignedLength()) + "-bytes)";
}

std::string AbstractFloatDataType::buildDescription() const {
    return buildIEEE754StandardDescription();
}

std::string AbstractFloatDataType::getMnemonic(Settings* settings) const {
    return name_;
}

std::string AbstractFloatDataType::getDescription() const {
    return description_;
}

int AbstractFloatDataType::getLength() const {
    return encodedLength_;
}

const std::type_info& AbstractFloatDataType::getValueClass(Settings* settings) const {
    return typeid(double);
}

std::string AbstractFloatDataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    return "??";
}

std::string AbstractFloatDataType::getDefaultLabelPrefix() const {
    std::string upperName = name_;
    std::transform(upperName.begin(), upperName.end(), upperName.begin(), ::toupper);
    return upperName;
}

std::string AbstractFloatDataType::getCTypeDeclaration(DataOrganization* dataOrganization) const {
    return hasLanguageDependantLength() ? "" : name_;
}

bool AbstractFloatDataType::hasLanguageDependantLength() const {
    return false;
}

} // namespace ghidra
