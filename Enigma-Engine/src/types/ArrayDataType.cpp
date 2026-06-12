/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra\ArrayDataType.h>

namespace ghidra {

ArrayDataType::ArrayDataType(DataType* dataType, int numElements, int elementLength, DataTypeManager* dtm,
              bool ownsDataType)
    : DataTypeImpl(dataType ? dataType->getCategoryPath() : CategoryPath::ROOT(), "array",
                   dtm ? dtm : (dataType ? dataType->getDataTypeManager() : nullptr)),
      numElements_(numElements),
      dataType_(dataType),
      elementLength_(elementLength > 0 ? elementLength : (dataType ? dataType->getAlignedLength() : 1)),
      ownsDataType_(ownsDataType),
      deleted_(false) {
    if (!dataType_) {
        throw std::invalid_argument("DataType must not be null");
    }
    if (numElements_ < 0) {
        throw std::invalid_argument("Number of array elements may not be negative");
    }
    name_ = dataType_->getName() + "[" + std::to_string(numElements_) + "]";
}

ArrayDataType::~ArrayDataType() {
    if (ownsDataType_) {
        delete dataType_;
    }
}

bool ArrayDataType::hasLanguageDependantLength() const {
    return dataType_->hasLanguageDependantLength();
}

bool ArrayDataType::isEquivalent(const DataType* obj) const {
    if (obj == this) return true;
    const Array* array = dynamic_cast<const Array*>(obj);
    if (!array) return false;
    
    if (numElements_ != array->getNumElements()) return false;
    if (!dataType_->isEquivalent(array->getDataType())) return false;
    if (getElementLength() != array->getElementLength()) return false;
    return true;
}

int ArrayDataType::getNumElements() const {
    return numElements_;
}

std::string ArrayDataType::getMnemonic(Settings* settings) const {
    return name_;
}

bool ArrayDataType::isZeroLength() const {
    return numElements_ == 0;
}

int ArrayDataType::getLength() const {
    if (numElements_ == 0) {
        return 1;
    }
    return numElements_ * getElementLength();
}

int ArrayDataType::getAlignedLength() const {
    return getLength();
}

std::string ArrayDataType::getDescription() const {
    return "Array of " + dataType_->getDisplayName();
}

DataType* ArrayDataType::getDataType() const {
    return dataType_;
}

DataType* ArrayDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<ArrayDataType*>(this);
    }
    DataType* clonedDataType = dataType_->clone(dtm);
    return new ArrayDataType(clonedDataType, numElements_, elementLength_, dtm,
                             clonedDataType != dataType_);
}

DataType* ArrayDataType::copy(DataTypeManager* dtm) const {
    return clone(dtm);
}

const std::type_info& ArrayDataType::getValueClass(Settings* settings) const {
    return typeid(void*);
}

int ArrayDataType::getElementLength() const {
    return elementLength_;
}

bool ArrayDataType::isDeleted() const {
    return deleted_;
}

CategoryPath ArrayDataType::getCategoryPath() const {
    return dataType_->getCategoryPath();
}

bool ArrayDataType::dependsOn(const DataType* dt) const {
    const DataType* myDt = getDataType();
    if (myDt == dt) return true;
    return myDt->dependsOn(dt);
}

std::string ArrayDataType::getDefaultLabelPrefix() const {
    return dataType_->getDefaultLabelPrefix() + "_" + ARRAY_LABEL_PREFIX;
}

std::string ArrayDataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    return "??";
}

} // namespace ghidra
