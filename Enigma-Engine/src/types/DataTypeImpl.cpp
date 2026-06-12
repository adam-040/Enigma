/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra\DataTypeImpl.h>

namespace ghidra {

int DataTypeImpl::computeAlignedLength(DataType* dataType) const {
    int len = dataType->getLength();
    if (len <= 0) {
        return len;
    }
    DataOrganization* org = dataType->getDataOrganization();
    if (!org) return len;
    
    int align = org->getSizeAlignment(len);
    int mod = len % align;
    if (mod != 0) {
        len += (align - mod);
    }
    return len;
}

DataTypeImpl::DataTypeImpl(const CategoryPath& path, const std::string& name, DataTypeManager* dataMgr)
    : AbstractDataType(path, name, dataMgr),
      defaultSettings_(nullptr),
      alignedLength_(0),
      hasAlignedLength_(false),
      lastChangeTime_(NO_LAST_CHANGE_TIME),
      lastChangeTimeInSourceArchive_(NO_LAST_CHANGE_TIME),
      sourceArchive_(nullptr) {
}

DataTypeImpl::~DataTypeImpl() = default;

const std::type_info& DataTypeImpl::getValueClass(Settings* settings) const {
    return typeid(void);
}

Settings* DataTypeImpl::getDefaultSettings() const {
    return defaultSettings_;
}

std::vector<SettingsDefinition*> DataTypeImpl::getSettingsDefinitions() const {
    return {};
}

int DataTypeImpl::getAlignedLength() const {
    if (!hasAlignedLength_) {
        alignedLength_ = computeAlignedLength(const_cast<DataTypeImpl*>(this));
        hasAlignedLength_ = true;
    }
    return alignedLength_;
}

int DataTypeImpl::getAlignment() const {
    int length = getLength();
    if (length < 0) {
        return 1;
    }
    DataOrganization* org = getDataOrganization();
    return org ? org->getAlignment(const_cast<DataTypeImpl*>(this)) : 1;
}

void DataTypeImpl::addParent(DataType* dt) {
    if (dt) {
        parentList_.push_back(dt);
    }
}

void DataTypeImpl::removeParent(DataType* dt) {
    auto it = std::find(parentList_.begin(), parentList_.end(), dt);
    if (it != parentList_.end()) {
        parentList_.erase(it);
    }
}

std::vector<DataType*> DataTypeImpl::getParents() const {
    return parentList_;
}

int64_t DataTypeImpl::getLastChangeTime() const {
    return lastChangeTime_;
}

int64_t DataTypeImpl::getLastChangeTimeInSourceArchive() const {
    return lastChangeTimeInSourceArchive_;
}

SourceArchive* DataTypeImpl::getSourceArchive() const {
    return sourceArchive_;
}

void DataTypeImpl::setSourceArchive(SourceArchive* archive) {
    sourceArchive_ = archive;
}

void DataTypeImpl::setLastChangeTime(int64_t lastChangeTime) {
    lastChangeTime_ = lastChangeTime;
}

void DataTypeImpl::setLastChangeTimeInSourceArchive(int64_t lastChangeTimeInSourceArchive) {
    lastChangeTimeInSourceArchive_ = lastChangeTimeInSourceArchive;
}

void DataTypeImpl::setDescription(const std::string& description) {
    throw std::runtime_error(name_ + " doesn't allow the description to be changed.");
}

bool DataTypeImpl::isEquivalent(const DataType* dt) const {
    if (this == dt) return true;
    if (!dt) return false;
    return typeid(*this) == typeid(*dt);
}

} // namespace ghidra
