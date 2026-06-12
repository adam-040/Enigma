/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra\TypedefDataType.h>

namespace ghidra {

TypedefDataType::TypedefDataType(const std::string& name, DataType* dt)
    : TypedefDataType(CategoryPath::ROOT(), name, dt, dt ? dt->getDataTypeManager() : nullptr) {}

TypedefDataType::TypedefDataType(const CategoryPath& path, const std::string& name, DataType* dt, DataTypeManager* dtm)
    : GenericDataType(path, name, dtm),
      dataType_(dt ? dt->clone(dtm) : nullptr),
      ownsDataType_(dt && dataType_ != dt),
      isAutoNamed_(false),
      deleted_(false) {
    if (!dt) {
        throw std::invalid_argument("TypeDef data type may not be null");
    }
}

TypedefDataType::~TypedefDataType() {
    if (ownsDataType_) {
        delete dataType_;
    }
}

void TypedefDataType::enableAutoNaming() {
    isAutoNamed_ = true;
}

bool TypedefDataType::isAutoNamed() const {
    return isAutoNamed_;
}

std::string TypedefDataType::getDefaultLabelPrefix() const {
    if (isAutoNamed()) {
        return getDataType()->getDefaultLabelPrefix();
    }
    return getName();
}

bool TypedefDataType::hasLanguageDependantLength() const {
    return dataType_->hasLanguageDependantLength();
}

bool TypedefDataType::isEquivalent(const DataType* obj) const {
    if (!obj) return false;
    if (obj == this) return true;
    const TypeDef* td = dynamic_cast<const TypeDef*>(obj);
    if (!td) return false;

    if (isAutoNamed_ != td->isAutoNamed()) return false;
    if (!isAutoNamed_ && getName() != td->getName()) return false;

    DataType* otherDataType = td->getDataType();
    return dataType_->isEquivalent(otherDataType);
}

std::string TypedefDataType::getMnemonic(Settings* settings) const {
    return name_;
}

DataType* TypedefDataType::getDataType() const {
    return dataType_;
}

std::string TypedefDataType::getDescription() const {
    return dataType_->getDescription();
}

bool TypedefDataType::isZeroLength() const {
    return dataType_->isZeroLength();
}

int TypedefDataType::getLength() const {
    return dataType_->getLength();
}

int TypedefDataType::getAlignedLength() const {
    return dataType_->getAlignedLength();
}

std::string TypedefDataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    return dataType_->getRepresentation(buf, settings, length);
}

const std::type_info& TypedefDataType::getValueClass(Settings* settings) const {
    return dataType_->getValueClass(settings);
}

DataType* TypedefDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<TypedefDataType*>(this);
    }
    TypedefDataType* newTypedef = new TypedefDataType(getCategoryPath(), getName(), dataType_, dtm);
    newTypedef->isAutoNamed_ = isAutoNamed_;
    return newTypedef;
}

DataType* TypedefDataType::copy(DataTypeManager* dtm) const {
    return clone(dtm);
}

std::string TypedefDataType::getName() const {
    if (isAutoNamed()) {
        return dataType_->getName() + " __((auto))";
    }
    return name_;
}

CategoryPath TypedefDataType::getCategoryPath() const {
    if (isAutoNamed()) {
        return getDataType()->getCategoryPath();
    }
    return categoryPath_;
}

DataType* TypedefDataType::getBaseDataType() const {
    if (auto td = dynamic_cast<TypeDef*>(dataType_)) {
        return td->getBaseDataType();
    }
    return dataType_;
}

bool TypedefDataType::isDeleted() const {
    return deleted_;
}

bool TypedefDataType::dependsOn(const DataType* dt) const {
    const DataType* myDt = getDataType();
    if (myDt == dt) return true;
    return myDt->dependsOn(dt);
}

} // namespace ghidra
