/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/AlignedStructureInspector.h>
#include <ghidra/Structure.h>
#include <ghidra/StructureInternal.h>
#include <ghidra/DataTypeComponent.h>
#include <stdexcept>

namespace ghidra {

// --- ReadOnlyComponentWrapper ---

AlignedStructureInspector::ReadOnlyComponentWrapper::ReadOnlyComponentWrapper(
        DataTypeComponent* component)
    : component_(component),
      ordinal_(component->getOrdinal()),
      offset_(component->getOffset()),
      length_(component->getLength()),
      dataType_(component->getDataType()) {}

DataType* AlignedStructureInspector::ReadOnlyComponentWrapper::getDataType() const {
    return dataType_;
}

DataType* AlignedStructureInspector::ReadOnlyComponentWrapper::getParent() const {
    return component_->getParent();
}

bool AlignedStructureInspector::ReadOnlyComponentWrapper::isBitFieldComponent() const {
    return component_->isBitFieldComponent();
}

bool AlignedStructureInspector::ReadOnlyComponentWrapper::isZeroBitFieldComponent() const {
    return component_->isZeroBitFieldComponent();
}

int AlignedStructureInspector::ReadOnlyComponentWrapper::getOrdinal() const {
    return ordinal_;
}

int AlignedStructureInspector::ReadOnlyComponentWrapper::getOffset() const {
    return offset_;
}

int AlignedStructureInspector::ReadOnlyComponentWrapper::getEndOffset() const {
    return offset_ + length_ - 1;
}

int AlignedStructureInspector::ReadOnlyComponentWrapper::getLength() const {
    return length_;
}

std::string AlignedStructureInspector::ReadOnlyComponentWrapper::getComment() const {
    return component_->getComment();
}

Settings* AlignedStructureInspector::ReadOnlyComponentWrapper::getDefaultSettings() const {
    return component_->getDefaultSettings();
}

DataTypeComponent* AlignedStructureInspector::ReadOnlyComponentWrapper::setComment(
        const std::string& comment) {
    throw std::runtime_error("UnsupportedOperationException");
}

std::string AlignedStructureInspector::ReadOnlyComponentWrapper::getFieldName() const {
    return component_->getFieldName();
}

DataTypeComponent* AlignedStructureInspector::ReadOnlyComponentWrapper::setFieldName(
        const std::string& fieldName) {
    throw std::runtime_error("UnsupportedOperationException");
}

bool AlignedStructureInspector::ReadOnlyComponentWrapper::isEquivalent(
        const DataTypeComponent* dtc) const {
    throw std::runtime_error("UnsupportedOperationException");
}

bool AlignedStructureInspector::ReadOnlyComponentWrapper::isUndefined() const {
    return component_->isUndefined();
}

void AlignedStructureInspector::ReadOnlyComponentWrapper::setDataType(DataType* dataType) {
    dataType_ = dataType;
}

void AlignedStructureInspector::ReadOnlyComponentWrapper::update(int ordinal, int offset, int len) {
    ordinal_ = ordinal;
    offset_ = offset;
    length_ = len;
}

// --- AlignedStructureInspector ---

AlignedStructureInspector::AlignedStructureInspector(StructureInternal* structure)
    : AlignedStructurePacker(structure, getComponentWrappers(structure)) {}

std::vector<InternalDataTypeComponent*> AlignedStructureInspector::getComponentWrappers(
        Structure* structure) {
    std::vector<InternalDataTypeComponent*> wrappers;
    auto components = structure->getDefinedComponents();
    for (auto* c : components) {
        wrappers.push_back(new ReadOnlyComponentWrapper(c));
    }
    return wrappers;
}

AlignedStructurePacker::StructurePackResult AlignedStructureInspector::packComponents(
        StructureInternal* structure) {
    AlignedStructureInspector packer(structure);
    return packer.pack();
}

} // namespace ghidra
