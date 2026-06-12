/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AbstractDataType.h
/// \brief Base class for DataType classes.
#pragma once

#include "DataType.h"
#include "DataOrganization.h"
#include "DataTypeManager.h"
#include <cstdint>

namespace ghidra {

/**
 * Base class for DataType classes. Many of the DataType methods are stubbed out 
 * so simple datatype classes can be created without implementing too many methods.
 * Translated from: ghidra.program.model.data.AbstractDataType
 */
class AbstractDataType : public virtual DataType {
protected:
    std::string name_;
    CategoryPath categoryPath_;
    DataTypeManager* dataMgr_;

    AbstractDataType(const CategoryPath& path, const std::string& name, DataTypeManager* dataTypeManager)
        : name_(name), categoryPath_(path), dataMgr_(dataTypeManager) {
        if (name.empty()) {
            throw std::invalid_argument("Name is null or empty!");
        }
    }

    static DataOrganization* getDataOrganization(DataTypeManager* dataMgr) {
        if (dataMgr) {
            return dataMgr->getDataOrganization();
        }
        return nullptr; // Needs DataOrganizationImpl::getDefaultOrganization() fallback later
    }

public:
    virtual ~AbstractDataType() = default;

    std::vector<TypeDefSettingsDefinition*> getTypeDefSettingsDefinitions() const override {
        return {};
    }

    CategoryPath getCategoryPath() const override {
        return categoryPath_;
    }

    DataTypeManager* getDataTypeManager() const override {
        return dataMgr_;
    }

    DataOrganization* getDataOrganization() const override {
        if (dataMgr_) return dataMgr_->getDataOrganization();
        return nullptr;
    }

    // DataTypePath getDataTypePath() const override { ... }

    std::string getName() const override {
        return name_;
    }

    std::string getPathName() const override {
        return categoryPath_.getPath(name_);
    }

    std::string getDisplayName() const override {
        return getName();
    }

    std::string getMnemonic(Settings* settings) const override {
        return name_;
    }

    bool isNotYetDefined() const override {
        return false;
    }

    bool isZeroLength() const override {
        return false;
    }

    std::string toString() const {
        return getDisplayName();
    }

    bool isDeleted() const override {
        return false;
    }

    void setName(const std::string& name) override {
        // default is immutable
    }

    void setNameAndCategory(const CategoryPath& path, const std::string& name) override {
        // default is immutable
    }

    void dataTypeSizeChanged(DataType* dt) override {}
    void dataTypeAlignmentChanged(DataType* dt) override {}
    void dataTypeDeleted(DataType* dt) override {}
    void dataTypeReplaced(DataType* oldDt, DataType* newDt) override {}
    void addParent(DataType* dt) override {}
    void removeParent(DataType* dt) override {}

    std::vector<DataType*> getParents() const override {
        return {};
    }

    bool dependsOn(const DataType* dt) const override {
        return false;
    }

    SourceArchive* getSourceArchive() const override {
        return nullptr;
    }

    void setSourceArchive(SourceArchive* archive) override {}

    int64_t getLastChangeTime() const override {
        return 0;
    }

    int64_t getLastChangeTimeInSourceArchive() const override {
        return 0;
    }

    void dataTypeNameChanged(DataType* dt, const std::string& oldName) override {}
    void replaceWith(DataType* dataType) override {}
    void setLastChangeTime(int64_t lastChangeTime) override {}
    void setLastChangeTimeInSourceArchive(int64_t lastChangeTimeInSourceArchive) override {}

    void setDescription(const std::string& description) override {}

    bool hasLanguageDependantLength() const override {
        return false;
    }

    std::string getDefaultLabelPrefix() const override {
        return "";
    }

    std::string getDefaultAbbreviatedLabelPrefix() const override {
        return getDefaultLabelPrefix();
    }

    void setCategoryPath(const CategoryPath& path) override {}

    std::string getDefaultLabelPrefix(MemBuffer* buf, Settings* settings, int len, DataTypeDisplayOptions* options) const override {
        return getDefaultLabelPrefix();
    }

    std::string getDefaultOffcutLabelPrefix(MemBuffer* buf, Settings* settings, int len, DataTypeDisplayOptions* options, int offcutLength) const override {
        return getDefaultLabelPrefix(buf, settings, len, options);
    }

    bool isEncodable() const override {
        return false;
    }

    std::vector<uint8_t> encodeValue(void* value, MemBuffer* buf, Settings* settings, int length) const override {
        throw DataTypeEncodeException("Encoding not supported");
    }

    std::vector<uint8_t> encodeRepresentation(const std::string& repr, MemBuffer* buf, Settings* settings, int length) const override {
        throw DataTypeEncodeException("Encoding not supported");
    }
    
    // Virtual implementations for base interface that derived classes must provide
    // clone, copy, getLength, getAlignedLength, getDescription, getValue, getValueClass, getRepresentation, isEquivalent, getAlignment
    virtual DataType* getReplacementBaseType() const override {
        return const_cast<AbstractDataType*>(this);
    }
};

} // namespace ghidra
