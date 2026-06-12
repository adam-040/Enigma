/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataTypeImpl.h
/// \brief Base implementation for dataTypes.
#pragma once

#include <vector>
#include <string>
#include <algorithm>
#include <cstdint>
#include "AbstractDataType.h"

namespace ghidra {

class DataTypeImpl : public AbstractDataType {
protected:
    Settings* defaultSettings_;
    mutable int alignedLength_;
    mutable bool hasAlignedLength_;

    std::vector<DataType*> parentList_;
    int64_t lastChangeTime_;
    int64_t lastChangeTimeInSourceArchive_;
    SourceArchive* sourceArchive_;

    DataTypeImpl(const CategoryPath& path, const std::string& name, DataTypeManager* dataMgr);

    int computeAlignedLength(DataType* dataType) const;

public:
    virtual ~DataTypeImpl();

    const std::type_info& getValueClass(Settings* settings) const override;

    Settings* getDefaultSettings() const override;

    std::vector<SettingsDefinition*> getSettingsDefinitions() const override;

    int getAlignedLength() const override;

    int getAlignment() const override;

    void addParent(DataType* dt) override;

    void removeParent(DataType* dt) override;

    std::vector<DataType*> getParents() const override;

    int64_t getLastChangeTime() const override;

    int64_t getLastChangeTimeInSourceArchive() const override;

    SourceArchive* getSourceArchive() const override;

    void setSourceArchive(SourceArchive* archive) override;

    void setLastChangeTime(int64_t lastChangeTime) override;

    void setLastChangeTimeInSourceArchive(int64_t lastChangeTimeInSourceArchive) override;

    void setDescription(const std::string& description) override;

    bool isEquivalent(const DataType* dt) const override;
};

} // namespace ghidra
