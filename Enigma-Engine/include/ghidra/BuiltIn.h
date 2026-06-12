/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file BuiltIn.h
/// \brief Base class for BuiltIn DataTypes.
#pragma once

#include "DataTypeImpl.h"

namespace ghidra {

/**
 * Base class for built-in Datatypes. A built-in data type is
 * searched for in the classpath and added automatically to the available
 * data types in the data type manager.
 * Translated from: ghidra.program.model.data.BuiltIn
 */
class BuiltIn : public DataTypeImpl {
protected:
    BuiltIn(const CategoryPath& path, const std::string& name, DataTypeManager* dataMgr);

public:
    virtual ~BuiltIn();

    DataType* copy(DataTypeManager* dtm) const override;

    std::vector<SettingsDefinition*> getSettingsDefinitions() const override;

    void setDefaultSettings(Settings* settings);

    bool isEquivalent(const DataType* dt) const override;

    int64_t getLastChangeTime() const override;

    virtual std::string getDecompilerDisplayName() const;

    std::string getCTypeDeclaration(DataOrganization* dataOrganization) const;
};

} // namespace ghidra
