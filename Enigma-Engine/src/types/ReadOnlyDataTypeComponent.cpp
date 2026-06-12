/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/ReadOnlyDataTypeComponent.h>
#include <ghidra/BitFieldDataType.h>
#include <ghidra/Composite.h>
#include <ghidra/DataType.h>

namespace ghidra {

ReadOnlyDataTypeComponent::ReadOnlyDataTypeComponent(
    DataType* dataType, DataType* parent,
    int length, int ordinal, int offset,
    const std::string& fieldName, const std::string& comment)
    : dataType_(dataType)
    , parent_(parent)
    , offset_(offset)
    , ordinal_(ordinal)
    , comment_(comment)
    , length_(length)
    , fieldName_(fieldName)
    , defaultSettings_(nullptr)
{
}

DataType* ReadOnlyDataTypeComponent::getDataType() const {
    return dataType_;
}

DataType* ReadOnlyDataTypeComponent::getParent() const {
    return parent_;
}

bool ReadOnlyDataTypeComponent::isBitFieldComponent() const {
    return dynamic_cast<BitFieldDataType*>(dataType_) != nullptr;
}

bool ReadOnlyDataTypeComponent::isZeroBitFieldComponent() const {
    auto* bf = dynamic_cast<BitFieldDataType*>(dataType_);
    return bf && bf->getBitSize() == 0;
}

int ReadOnlyDataTypeComponent::getOrdinal() const {
    return ordinal_;
}

int ReadOnlyDataTypeComponent::getOffset() const {
    return offset_;
}

int ReadOnlyDataTypeComponent::getEndOffset() const {
    return offset_ + length_ - 1;
}

int ReadOnlyDataTypeComponent::getLength() const {
    if (length_ == 0) {
        return 1;
    }
    return length_;
}

std::string ReadOnlyDataTypeComponent::getComment() const {
    return comment_;
}

DataTypeComponent* ReadOnlyDataTypeComponent::setComment(const std::string& comment) {
    return this;
}

std::string ReadOnlyDataTypeComponent::getFieldName() const {
    if (fieldName_.empty()) {
        return getDefaultFieldName();
    }
    return fieldName_;
}

DataTypeComponent* ReadOnlyDataTypeComponent::setFieldName(const std::string& fieldName) {
    return this;
}

Settings* ReadOnlyDataTypeComponent::getDefaultSettings() const {
    if (!defaultSettings_) {
        auto* settings = new SettingsImpl(true);
        settings->setDefaultSettings(dataType_->getDefaultSettings());
        defaultSettings_ = settings;
    }
    return defaultSettings_;
}

bool ReadOnlyDataTypeComponent::isEquivalent(const DataTypeComponent* dtc) const {
    DataType* myDt = getDataType();
    DataType* otherDt = dtc->getDataType();
    int otherLength = dtc->getLength();
    DataType* myParent = getParent();
    bool aligned = false;
    auto* comp = dynamic_cast<Composite*>(myParent);
    if (comp) {
        aligned = comp->isPackingEnabled();
    }
    if ((!aligned && (offset_ != dtc->getOffset())) ||
        (!aligned && (length_ != otherLength)) ||
        ordinal_ != dtc->getOrdinal() ||
        !isSameString(getFieldName(), dtc->getFieldName()) ||
        !isSameString(getComment(), dtc->getComment())) {
        return false;
    }
    return myDt->isEquivalent(otherDt);
}

bool ReadOnlyDataTypeComponent::isUndefined() const {
    return dataType_ == nullptr;
}

bool ReadOnlyDataTypeComponent::isSameString(const std::string& s1, const std::string& s2) {
    return s1 == s2;
}

} // namespace ghidra
