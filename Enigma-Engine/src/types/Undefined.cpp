/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Undefined.cpp
/// \brief Identifies an undefined data type.
#include "ghidra/Undefined.h"
#include "ghidra/DefaultDataType.h"
#include "ghidra/ArrayDataType.h"
#include <array>

namespace ghidra {

namespace {
std::array<Undefined*, 8>& slots() {
    static std::array<Undefined*, 8> s = { nullptr };
    return s;
}
}

Undefined::Undefined(const std::string& name, DataTypeManager* dtm, int size)
    : BuiltIn(CategoryPath::ROOT(), name, dtm), size_(size) {}

Undefined::~Undefined() = default;

int Undefined::getLength() const {
    return size_;
}

std::string Undefined::getDescription() const {
    return "Undefined";
}

DataType* Undefined::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<Undefined*>(this);
    }
    return new Undefined(getName(), dtm, size_);
}

std::string Undefined::getRepresentation(MemBuffer* /*buf*/, Settings* /*settings*/, int /*length*/) const {
    return "";
}

DataType* Undefined::getUndefinedDataType(int size) {
    if (size < 1) {
        return &DefaultDataType::dataType();
    }
    if (size > 8) {
        return new ArrayDataType(&DefaultDataType::dataType(), size, 1);
    }
    auto& s = slots();
    if (s[size - 1] == nullptr) {
        std::string nm = "undefined" + std::to_string(size);
        s[size - 1] = new Undefined(nm, nullptr, size);
    }
    return s[size - 1];
}

bool Undefined::isUndefined(const DataType* dataType) {
    if (dataType == nullptr) return false;
    if (dynamic_cast<const DefaultDataType*>(dataType) != nullptr) return true;
    if (dynamic_cast<const Undefined*>(dataType) != nullptr) return true;
    return isUndefinedArray(dataType);
}

bool Undefined::isUndefinedArray(const DataType* dataType) {
    if (dataType == nullptr) return false;
    auto* arr = dynamic_cast<const ArrayDataType*>(dataType);
    if (arr == nullptr) return false;
    const DataType* base = arr->getDataType();
    return dynamic_cast<const Undefined*>(base) != nullptr ||
           dynamic_cast<const DefaultDataType*>(base) != nullptr;
}

} // namespace ghidra
