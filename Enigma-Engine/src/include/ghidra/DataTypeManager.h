/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataTypeManager.h
/// \brief Data type manager interface
/// Translated from: ghidra.program.model.data.DataTypeManager
#pragma once

#include <ghidra/DataType.h>
#include <ghidra/DataOrganization.h>
#include <ghidra/CategoryPath.h>
#include <ghidra/ArchiveType.h>
#include <ghidra/UniversalID.h>
#include <string>
#include <vector>
#include <set>
#include <unordered_map>

namespace ghidra {

class DataTypePath;
class Pointer;
class SourceArchive;
class Category;
class PrototypeModel;
class DataTypeConflictHandler;

/**
 * Interface for managing data types.
 */
class DataTypeManager {
public:
    virtual ~DataTypeManager() = default;

    static constexpr long DEFAULT_DATATYPE_ID = 0;
    static constexpr long NULL_DATATYPE_ID = -1;
    static constexpr long BAD_DATATYPE_ID = -2;

    static inline const std::string BUILT_IN_DATA_TYPES_NAME = "BuiltInTypes";

    /// Archive key constants
    static constexpr long LOCAL_ARCHIVE_KEY = 0;
    static constexpr long BUILT_IN_ARCHIVE_KEY = 1;
    static inline const UniversalID LOCAL_ARCHIVE_UNIVERSAL_ID = UniversalID(LOCAL_ARCHIVE_KEY);
    static inline const UniversalID BUILT_IN_ARCHIVE_UNIVERSAL_ID = UniversalID(BUILT_IN_ARCHIVE_KEY);

    // === Existing pure virtual methods (must be overridden) ===

    virtual const std::string& getName() const = 0;
    virtual DataType* getDataType(const CategoryPath& categoryPath, const std::string& name) = 0;
    // Datatype ids are 64-bit: composite/typedef/pointer/array/enum/function
    // ids carry a 2^56 type tag plus an ordinal (Ghidra DataTypeDB ids), which
    // does not fit in a 32-bit long.
    virtual DataType* getDataType(int64_t id) = 0;
    virtual std::vector<DataType*> getDataTypes() = 0;
    virtual std::vector<std::string> getDefinedCallingConventionNames() const = 0;
    virtual std::vector<std::string> getKnownCallingConventionNames() const = 0;
    virtual DataOrganization* getDataOrganization() const = 0;

    // === New virtual methods with default implementations ===

    virtual UniversalID getUniversalID() const { return UniversalID(0); }
    virtual bool containsCategory(const CategoryPath& path) const { return false; }
    virtual std::string getUniqueName(const CategoryPath& path, const std::string& baseName) { return baseName; }

    virtual DataType* resolve(DataType* dataType, DataTypeConflictHandler* handler) { return dataType; }
    virtual DataType* addDataType(DataType* dataType, DataTypeConflictHandler* handler) { return dataType; }

    virtual void findDataTypes(const std::string& name, std::vector<DataType*>& list) {}
    virtual void findDataTypes(const std::string& name, std::vector<DataType*>& list, bool caseSensitive) {}

    virtual DataType* replaceDataType(DataType* existingDt, DataType* replacementDt, bool updateCategoryPath) { return replacementDt; }

    virtual DataType* getDataType(const std::string& dataTypePath) { return nullptr; }
    virtual DataType* getDataType(const DataTypePath& dataTypePath) { return nullptr; }

    virtual long getID(DataType* dt) { return -1; }

    virtual Category* getCategory(long categoryID) { return nullptr; }
    virtual Category* getCategory(const CategoryPath& path) { return nullptr; }

    virtual bool remove(DataType* dataType) { return false; }
    virtual bool contains(DataType* dataType) const { return false; }

    virtual Category* createCategory(const CategoryPath& path) { return nullptr; }

    virtual void setName(const std::string& name) {}
    virtual bool isUpdatable() const { return false; }
    virtual void close() {}

    virtual Pointer* getPointer(DataType* datatype) { return nullptr; }
    virtual Pointer* getPointer(DataType* datatype, int size) { return nullptr; }

    virtual Category* getRootCategory() { return nullptr; }

    virtual bool isFavorite(DataType* datatype) { return false; }
    virtual void setFavorite(DataType* datatype, bool isFavorite) {}
    virtual std::vector<DataType*> getFavorites() { return {}; }

    virtual int getCategoryCount() const { return 0; }
    virtual int getDataTypeCount(bool includePointersAndArrays) const { return 0; }

    virtual void findEnumValueNames(long value, std::set<std::string>& enumValueNames) {}

    virtual DataType* getDataType(SourceArchive* sourceArchive, UniversalID datatypeID) { return nullptr; }
    virtual DataType* findDataTypeForID(UniversalID datatypeID) { return nullptr; }

    virtual int64_t getLastChangeTimeForMyManager() { return 0; }

    virtual SourceArchive* getSourceArchive(UniversalID sourceID) { return nullptr; }
    virtual ArchiveType getType() const { return ArchiveType::TEMPORARY; }

    virtual std::vector<DataType*> getDataTypes(SourceArchive* sourceArchive) { return {}; }
    virtual SourceArchive* getLocalSourceArchive() { return nullptr; }

    virtual void associateDataTypeWithArchive(DataType* datatype, SourceArchive* archive) {}
    virtual void disassociate(DataType* datatype) {}

    virtual bool updateSourceArchiveName(const std::string& archiveFileID, const std::string& name) { return false; }
    virtual bool updateSourceArchiveName(UniversalID sourceID, const std::string& name) { return false; }

    virtual std::vector<SourceArchive*> getSourceArchives() { return {}; }
    virtual void removeSourceArchive(SourceArchive* sourceArchive) {}

    virtual SourceArchive* resolveSourceArchive(SourceArchive* sourceArchive) { return sourceArchive; }

    virtual bool allowsDefaultBuiltInSettings() const { return false; }
    virtual bool allowsDefaultComponentSettings() const { return false; }

    virtual PrototypeModel* getDefaultCallingConvention() { return nullptr; }
    virtual PrototypeModel* getCallingConvention(const std::string& name) { return nullptr; }

    virtual void flushEvents() {}
};

} // namespace ghidra
