/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Composite.cpp
/// \brief Implementation of Composite default methods
#include "ghidra/Composite.h"

namespace ghidra {

DataTypeComponent* Composite::findComponent(const std::string& fieldName) const {
    if (getNumDefinedComponents() == 0) return nullptr;
    for (DataTypeComponent* dtc : getDefinedComponents()) {
        if (dtc->getFieldName() == fieldName) {
            return dtc;
        }
    }
    return nullptr;
}

std::vector<DataTypeComponent*> Composite::findComponents(const std::string& name) const {
    std::vector<DataTypeComponent*> list;
    if (getNumDefinedComponents() == 0) return list;
    for (DataTypeComponent* dtc : getDefinedComponents()) {
        if (dtc->getFieldName() == name) {
            list.push_back(dtc);
        }
    }
    return list;
}

bool Composite::isPackingEnabled() const {
    return getPackingType() != PackingType::DISABLED;
}

bool Composite::hasExplicitPackingValue() const {
    return getPackingType() == PackingType::EXPLICIT;
}

bool Composite::hasDefaultPacking() const {
    return getPackingType() == PackingType::DEFAULT;
}

void Composite::pack(int packingValue) {
    setExplicitPackingValue(packingValue);
}

bool Composite::isDefaultAligned() const {
    return getAlignmentType() == AlignmentType::DEFAULT;
}

bool Composite::isMachineAligned() const {
    return getAlignmentType() == AlignmentType::MACHINE;
}

bool Composite::hasExplicitMinimumAlignment() const {
    return getAlignmentType() == AlignmentType::EXPLICIT;
}

void Composite::align(int minAlignment) {
    setExplicitMinimumAlignment(minAlignment);
}

} // namespace ghidra
