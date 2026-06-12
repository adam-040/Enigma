/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataTypeComponentImpl.cpp
/// \brief Implementation of DataTypeComponentImpl
#include "ghidra/DataTypeComponentImpl.h"

namespace ghidra {

DataTypeComponentImpl::DataTypeComponentImpl(DataType* dataType, int length, int ordinal, int offset,
                                             const std::string& fieldName, const std::string& comment,
                                             DataType* parent, bool ownsDataType)
    : dataType_(dataType), parent_(parent), ownsDataType_(ownsDataType), length_(length),
      ordinal_(ordinal), offset_(offset), fieldName_(fieldName), comment_(comment) {}

DataTypeComponentImpl::~DataTypeComponentImpl() {
    if (ownsDataType_) {
        delete dataType_;
    }
}

bool DataTypeComponentImpl::isBitFieldComponent() const {
    return dynamic_cast<BitFieldDataType*>(dataType_) != nullptr;
}

bool DataTypeComponentImpl::isZeroBitFieldComponent() const {
    auto* bitFieldDataType = dynamic_cast<BitFieldDataType*>(dataType_);
    return bitFieldDataType && bitFieldDataType->isZeroLength();
}

bool DataTypeComponentImpl::isEquivalent(const DataTypeComponent* dtc) const {
    if (!dtc) return false;
    if (ordinal_ != dtc->getOrdinal()) return false;
    if (offset_ != dtc->getOffset()) return false;
    if (length_ != dtc->getLength()) return false;
    if (!dataType_ || !dtc->getDataType()) return false;
    return dataType_->isEquivalent(dtc->getDataType());
}

DataTypeComponent* DataTypeComponentImpl::setComment(const std::string& comment) {
    comment_ = comment;
    return this;
}

DataTypeComponent* DataTypeComponentImpl::setFieldName(const std::string& fieldName) {
    fieldName_ = fieldName;
    return this;
}

void DataTypeComponentImpl::replaceDataType(DataType* dataType, bool ownsDataType) {
    if (ownsDataType_ && dataType_ != dataType) {
        delete dataType_;
    }
    dataType_ = dataType;
    ownsDataType_ = ownsDataType;
}

} // namespace ghidra
