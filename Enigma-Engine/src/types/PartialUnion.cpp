/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PartialUnion.cpp
/// \brief Data-type representing an unspecified piece of a parent Union data-type.
#include "ghidra/PartialUnion.h"
#include "ghidra/Union.h"
#include "ghidra/Undefined.h"
#include "ghidra/MemBuffer.h"
#include <stdexcept>
#include <typeinfo>

namespace ghidra {

PartialUnion::PartialUnion(DataTypeManager* dtm, DataType* parent, int off, int sz)
    : AbstractDataType(CategoryPath::ROOT(), "partialunion", dtm),
      unionDataType(parent), offset(off), size(sz) {}

DataType* PartialUnion::clone(DataTypeManager* dtm) const {
    throw std::runtime_error("may not be cloned");
}

int PartialUnion::getLength() const {
    return size;
}

int PartialUnion::getAlignedLength() const {
    return getLength();
}

std::string PartialUnion::getDescription() const {
    return "Partial Union (internal)";
}

std::string PartialUnion::getRepresentation(MemBuffer* /*buf*/, Settings* /*settings*/, int /*length*/) const {
    return std::string();
}

std::vector<SettingsDefinition*> PartialUnion::getSettingsDefinitions() const {
    return unionDataType ? unionDataType->getSettingsDefinitions() : std::vector<SettingsDefinition*>();
}

Settings* PartialUnion::getDefaultSettings() const {
    return unionDataType ? unionDataType->getDefaultSettings() : nullptr;
}

DataType* PartialUnion::copy(DataTypeManager* dtm) const {
    throw std::runtime_error("may not be copied");
}

const std::type_info& PartialUnion::getValueClass(Settings* settings) const {
    if (unionDataType) {
        return unionDataType->getValueClass(settings);
    }
    return typeid(void);
}

bool PartialUnion::isEquivalent(const DataType* dt) const {
    if (dt == nullptr) return false;
    const PartialUnion* op = dynamic_cast<const PartialUnion*>(dt);
    if (op == nullptr) return false;
    if (offset != op->offset || size != op->size) return false;
    if (unionDataType == nullptr) return op->unionDataType == nullptr;
    if (op->unionDataType == nullptr) return false;
    return unionDataType->isEquivalent(op->unionDataType);
}

int PartialUnion::getAlignment() const {
    return 0;
}

DataType* PartialUnion::getStrippedDataType() const {
    return Undefined::getUndefinedDataType(size);
}

} // namespace ghidra
