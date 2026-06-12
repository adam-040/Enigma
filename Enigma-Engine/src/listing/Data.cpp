/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Data.cpp
/// \brief Data representation in the program listing
#include <ghidra/Data.h>
#include <ghidra/DataType.h>
#include <sstream>

namespace ghidra {

Data::Data(Program* program, Address address, DataType* dataType, int length)
    : CodeUnit(program, address, dataType), length_(length) {}

int Data::getLength() const { return length_; }

DataType* Data::getBaseDataType() const {
    return getDataType();
}

int Data::getNumComponents() const { return static_cast<int>(components_.size()); }

Data* Data::getComponent(int index) const {
    if (index >= 0 && index < static_cast<int>(components_.size())) {
        return components_[index];
    }
    return nullptr;
}

void Data::addComponent(Data* component) {
    if (component) {
        component->setParent(this);
        components_.push_back(component);
    }
}

bool Data::isPointer() const {
    DataType* dt = getDataType();
    return dt && dt->getName().find('*') != std::string::npos;
}

bool Data::isString() const {
    DataType* dt = getDataType();
    return dt && (dt->getName() == "string" || dt->getName() == "char");
}

bool Data::isUnicode() const {
    DataType* dt = getDataType();
    return dt && dt->getName().find("unicode") != std::string::npos;
}

bool Data::isArray() const {
    DataType* dt = getDataType();
    return dt && dt->getName().find('[') != std::string::npos;
}

bool Data::isStructure() const {
    DataType* dt = getDataType();
    return dt && dt->getName().find("struct") != std::string::npos;
}

bool Data::isUnion() const {
    DataType* dt = getDataType();
    return dt && dt->getName().find("union") != std::string::npos;
}

std::string Data::getDefaultLabelRepresentation() const {
    DataType* dt = getDataType();
    if (dt) return dt->getName();
    return "data";
}

Data* Data::getPrimitiveAt(int offset) const {
    if (offset < 0 || offset >= length_) return nullptr;
    for (auto* comp : components_) {
        if (!comp) continue;
        int compOffset = comp->getComponentOffset();
        int compLen = comp->getLength();
        if (compOffset <= offset && offset < compOffset + compLen) {
            return comp->getPrimitiveAt(offset - compOffset);
        }
    }
    return const_cast<Data*>(this);
}

bool Data::isDefined() const {
    return dataType_ != nullptr;
}

std::string Data::toString() const {
    std::ostringstream ss;
    ss << getAddress().toString() << ": ";
    if (getDataType()) {
        ss << getDataType()->getName();
    } else {
        ss << "undefined";
    }
    ss << " (" << length_ << " bytes)";
    return ss.str();
}

} // namespace ghidra
