/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataTypeManagerImpl.h
/// \brief Concrete standard data type manager implementation
#pragma once

#include <ghidra/DataTypeManager.h>
#include <ghidra/DataOrganizationImpl.h>
#include <vector>
#include <unordered_map>
#include <memory>
#include <string>

namespace ghidra {

class DataTypeManagerImpl : public DataTypeManager {
public:
    DataTypeManagerImpl();
    explicit DataTypeManagerImpl(const std::string& name);
    ~DataTypeManagerImpl() override;

    const std::string& getName() const override;
    void setName(const std::string& name) { name_ = name; }

    DataType* getDataType(const CategoryPath& categoryPath, const std::string& name) override;
    DataType* getDataType(long id) override;
    std::vector<DataType*> getDataTypes() override;
    DataType* resolve(DataType* dataType, DataTypeConflictHandler* handler) override;
    
    std::vector<std::string> getDefinedCallingConventionNames() const override { return {}; }
    std::vector<std::string> getKnownCallingConventionNames() const override { return {}; }
    DataOrganization* getDataOrganization() const override;

    // Methods for adding/registering custom and composite types
    DataType* addDataType(DataType* dt);
    DataType* addDataTypeWithId(DataType* dt, long id);
    void removeDataType(DataType* dt);
    void clearAllDataTypes();
    long getNextId();
    long getDataTypeId(DataType* dt) const;

private:
    void populateBuiltInTypes();

    std::string name_ = "ProgramDB";
    std::unique_ptr<DataOrganizationImpl> dataOrganization_;
    std::vector<std::unique_ptr<DataType>> types_;
    std::unordered_map<std::string, DataType*> typesByPath_;
    std::unordered_map<long, DataType*> typesById_;
    long nextId_ = 1000; // Built-ins use < 1000, custom starts at 1000
};

} // namespace ghidra
