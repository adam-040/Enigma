/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataType.h
/// \brief Base interface for all Ghidra data types
#pragma once

#include <string>
#include <vector>
#include <memory>
#include <typeinfo>
#include <cstdint>
#include "CategoryPath.h"

namespace ghidra {

// Forward declarations for dependencies
class Settings;
class SettingsDefinition;
class TypeDefSettingsDefinition;
class DataTypeManager;
class DataTypePath;
class MemBuffer;
class DataTypeDisplayOptions;
class SourceArchive;
class DataOrganization;
class UniversalID;
class DataTypeEncodeException : public std::runtime_error {
public:
    explicit DataTypeEncodeException(const std::string& msg) : std::runtime_error(msg) {}
};

/**
 * The interface that all datatypes must implement.
 * Translated from: ghidra.program.model.data.DataType
 */
class DataType {
public:
    virtual ~DataType() = default;

    static inline const std::string CONFLICT_SUFFIX = ".conflict";
    static inline const std::string TYPEDEF_ATTRIBUTE_PREFIX = "__((";
    static inline const std::string TYPEDEF_ATTRIBUTE_SUFFIX = "))";

    static constexpr int64_t NO_SOURCE_SYNC_TIME = 0LL;
    static constexpr int64_t NO_LAST_CHANGE_TIME = 0LL;

    // TODO: DEFAULT and VOID singletons can be initialized in a cpp file or getter later.

    virtual bool hasLanguageDependantLength() const = 0;

    virtual std::vector<SettingsDefinition*> getSettingsDefinitions() const = 0;

    virtual std::vector<TypeDefSettingsDefinition*> getTypeDefSettingsDefinitions() const = 0;

    virtual Settings* getDefaultSettings() const = 0;

    virtual DataType* clone(DataTypeManager* dtm) const = 0;

    virtual DataType* copy(DataTypeManager* dtm) const = 0;

    virtual CategoryPath getCategoryPath() const = 0;

    // virtual DataTypePath getDataTypePath() const = 0; // Requires DataTypePath

    virtual void setCategoryPath(const CategoryPath& path) = 0;

    virtual DataTypeManager* getDataTypeManager() const = 0;

    virtual std::string getDisplayName() const = 0;

    virtual std::string getName() const = 0;

    virtual std::string getPathName() const = 0;

    virtual void setName(const std::string& name) = 0;

    virtual void setNameAndCategory(const CategoryPath& path, const std::string& name) = 0;

    virtual std::string getMnemonic(Settings* settings) const = 0;

    virtual int getLength() const = 0;

    virtual int getAlignedLength() const = 0;

    virtual bool isZeroLength() const = 0;

    virtual bool isNotYetDefined() const = 0;

    virtual std::string getDescription() const = 0;

    virtual void setDescription(const std::string& description) = 0;

    // virtual void* getValue(MemBuffer* buf, Settings* settings, int length) const = 0;

    virtual bool isEncodable() const = 0;

    virtual std::vector<uint8_t> encodeValue(void* value, MemBuffer* buf, Settings* settings, int length) const = 0;

    virtual const std::type_info& getValueClass(Settings* settings) const = 0;

    virtual std::string getDefaultLabelPrefix() const = 0;

    virtual std::string getDefaultAbbreviatedLabelPrefix() const = 0;

    virtual std::string getDefaultLabelPrefix(MemBuffer* buf, Settings* settings, int len, DataTypeDisplayOptions* options) const = 0;

    virtual std::string getDefaultOffcutLabelPrefix(MemBuffer* buf, Settings* settings, int len, DataTypeDisplayOptions* options, int offcutOffset) const = 0;

    virtual std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const = 0;

    virtual std::vector<uint8_t> encodeRepresentation(const std::string& repr, MemBuffer* buf, Settings* settings, int length) const = 0;

    virtual bool isDeleted() const = 0;

    virtual bool isEquivalent(const DataType* dt) const = 0;

    virtual void dataTypeSizeChanged(DataType* dt) = 0;

    virtual void dataTypeAlignmentChanged(DataType* dt) = 0;

    virtual void dataTypeDeleted(DataType* dt) = 0;

    virtual void dataTypeReplaced(DataType* oldDt, DataType* newDt) = 0;

    virtual void addParent(DataType* dt) = 0;

    virtual void removeParent(DataType* dt) = 0;

    virtual void dataTypeNameChanged(DataType* dt, const std::string& oldName) = 0;

    virtual std::vector<DataType*> getParents() const = 0;

    virtual int getAlignment() const = 0;

    virtual bool dependsOn(const DataType* dt) const = 0;

    virtual SourceArchive* getSourceArchive() const = 0;

    virtual void setSourceArchive(SourceArchive* archive) = 0;

    virtual int64_t getLastChangeTime() const = 0;

    virtual int64_t getLastChangeTimeInSourceArchive() const = 0;

    // virtual UniversalID getUniversalID() const = 0;

    virtual void replaceWith(DataType* dataType) = 0;

    virtual void setLastChangeTime(int64_t lastChangeTime) = 0;

    virtual void setLastChangeTimeInSourceArchive(int64_t lastChangeTimeInSourceArchive) = 0;

    virtual DataOrganization* getDataOrganization() const = 0;

    virtual DataType* getReplacementBaseType() const = 0;
};

} // namespace ghidra
