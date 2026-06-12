/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AbstractComplexDataType.cpp
/// \brief Complex number data type base implementation
#include "ghidra/AbstractComplexDataType.h"

namespace ghidra {

AbstractComplexDataType::AbstractComplexDataType(const std::string& name, AbstractFloatDataType* floatType, DataTypeManager* dtm)
    : BuiltIn(CategoryPath::ROOT(), name, dtm), floatType_(floatType) {
}

AbstractComplexDataType::~AbstractComplexDataType() = default;

std::string AbstractComplexDataType::getMnemonic(Settings* settings) const {
    return name_;
}

int AbstractComplexDataType::getLength() const {
    return floatType_ ? floatType_->getLength() * 2 : 0;
}

int AbstractComplexDataType::getAlignedLength() const {
    return getLength();
}

std::string AbstractComplexDataType::getDescription() const {
    return "The data type for a complex number: a + bi; consisting of two " +
        (floatType_ ? floatType_->getName() : "unknown") + " values";
}

std::string AbstractComplexDataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    return "??";
}

} // namespace ghidra
