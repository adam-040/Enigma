/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra\CompositeDataTypeImpl.h>

namespace ghidra {

CompositeDataTypeImpl::CompositeDataTypeImpl(const CategoryPath& path, const std::string& name, DataTypeManager* dtm)
    : GenericDataType(path, name, dtm),
      minimumAlignment_(DEFAULT_ALIGNMENT),
      packing_(NO_PACKING) {}

CompositeDataTypeImpl::~CompositeDataTypeImpl() = default;

int CompositeDataTypeImpl::getPreferredComponentLength(DataType* dataType, int length) const {
    if (DataTypeComponent::usesZeroLengthComponent(dataType)) return 0;
    if (length > 0) return length;
    int dtLen = dataType->getLength();
    return (dtLen > 0) ? dtLen : 1;
}

DataTypeComponent* CompositeDataTypeImpl::addBitField(DataType* baseDataType, int bitSize, const std::string& componentName, const std::string& comment) {
    auto* bitField = new BitFieldDataType(baseDataType, bitSize);
    DataTypeComponent* component = add(bitField, bitField->getStorageSize(), componentName, comment);
    if (auto* concrete = dynamic_cast<DataTypeComponentImpl*>(component)) {
        concrete->setOwnsDataType(true);
    }
    return component;
}

bool CompositeDataTypeImpl::isNotYetDefined() const {
    return getNumComponents() == 0 && !isPackingEnabled();
}

bool CompositeDataTypeImpl::isPartOf(const DataType* dataType) const {
    auto comps = getDefinedComponents();
    for (auto c : comps) {
        if (c->getDataType() == dataType) return true;
    }
    return false;
}

int CompositeDataTypeImpl::getAlignedLength() const {
    return getLength();
}

std::string CompositeDataTypeImpl::getMnemonic(Settings*) const {
    return getDisplayName();
}

const std::type_info& CompositeDataTypeImpl::getValueClass(Settings*) const {
    return typeid(void);
}

PackingType CompositeDataTypeImpl::getPackingType() const {
    if (packing_ < DEFAULT_PACKING) return PackingType::DISABLED;
    if (packing_ == DEFAULT_PACKING) return PackingType::DEFAULT;
    return PackingType::EXPLICIT;
}

void CompositeDataTypeImpl::setPackingEnabled(bool enabled) {
    packing_ = enabled ? DEFAULT_PACKING : NO_PACKING;
}

void CompositeDataTypeImpl::setToDefaultPacking() {
    packing_ = DEFAULT_PACKING;
}

int CompositeDataTypeImpl::getExplicitPackingValue() const {
    return packing_;
}

void CompositeDataTypeImpl::setExplicitPackingValue(int packingValue) {
    if (packingValue <= 0) throw std::invalid_argument("explicit packing value must be positive");
    packing_ = packingValue;
}

AlignmentType CompositeDataTypeImpl::getAlignmentType() const {
    if (minimumAlignment_ < DEFAULT_ALIGNMENT) return AlignmentType::MACHINE;
    if (minimumAlignment_ == DEFAULT_ALIGNMENT) return AlignmentType::DEFAULT;
    return AlignmentType::EXPLICIT;
}

void CompositeDataTypeImpl::setToDefaultAligned() {
    minimumAlignment_ = DEFAULT_ALIGNMENT;
}

void CompositeDataTypeImpl::setToMachineAligned() {
    minimumAlignment_ = MACHINE_ALIGNMENT;
}

int CompositeDataTypeImpl::getExplicitMinimumAlignment() const {
    return minimumAlignment_;
}

void CompositeDataTypeImpl::setExplicitMinimumAlignment(int minAlignment) {
    if (minAlignment <= 0) throw std::invalid_argument("explicit minimum alignment must be positive");
    minimumAlignment_ = minAlignment;
}

int CompositeDataTypeImpl::alignTo(int offset, int alignment) const {
    if (alignment <= 1) return offset;
    int remainder = offset % alignment;
    return remainder == 0 ? offset : offset + (alignment - remainder);
}

int CompositeDataTypeImpl::getBitFieldAlignment(BitFieldDataType* bitField, BitFieldPacking* packing) const {
    int alignment = std::max(1, bitField->getAlignment());
    if (packing && !packing->isTypeAlignmentEnabled()) {
        alignment = 1;
        if (bitField->getDeclaredBitSize() == 0) {
            int zeroLengthBoundary = packing->getZeroLengthBoundary();
            alignment = zeroLengthBoundary > 0 ? zeroLengthBoundary : bitField->getBaseTypeSize();
        }
    }
    return alignment;
}

void CompositeDataTypeImpl::repack() {}

std::string CompositeDataTypeImpl::getRepresentation(MemBuffer*, Settings*, int) const {
    if (isNotYetDefined()) return "";
    return "";
}

} // namespace ghidra
