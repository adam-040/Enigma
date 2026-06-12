/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 */
/// \file DataType.h
/// \brief Base interface for all data types
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <ghidra/program/model/data/CategoryPath.h>
#include <ghidra/program/model/data/DataTypePath.h>

namespace ghidra {

class DataTypeManager;
class DataOrganization;
class Settings;
class SettingsDefinition;
class TypeDefSettingsDefinition;
class MemBuffer;
class SourceArchive;
class UniversalID;

class DataType {
public:
    static constexpr const char* CONFLICT_SUFFIX = ".conflict";
    static constexpr const char* TYPEDEF_ATTRIBUTE_PREFIX = "____((";
    static constexpr const char* TYPEDEF_ATTRIBUTE_SUFFIX = "))";
    static constexpr int64_t NO_SOURCE_SYNC_TIME = 0;
    static constexpr int64_t NO_LAST_CHANGE_TIME = 0;

    // Singleton instances managed by specific subclasses
    static DataType* DEFAULT;
    static DataType* VOID;

    virtual ~DataType() = default;

    virtual bool hasLanguageDependantLength() const = 0;
    virtual std::vector<SettingsDefinition*> getSettingsDefinitions() const = 0;
    virtual std::vector<TypeDefSettingsDefinition*> getTypeDefSettingsDefinitions() const = 0;
    virtual std::shared_ptr<Settings> getDefaultSettings() const = 0;
    virtual std::shared_ptr<DataType> clone(const std::shared_ptr<DataTypeManager>& dtm) = 0;
    virtual std::shared_ptr<DataType> copy(const std::shared_ptr<DataTypeManager>& dtm) = 0;
    virtual CategoryPath getCategoryPath() const = 0;
    virtual DataTypePath getDataTypePath() const = 0;
    virtual void setCategoryPath(const CategoryPath& path) = 0;
    virtual DataTypeManager* getDataTypeManager() const = 0;
    virtual std::string getDisplayName() const = 0;
    virtual std::string getName() const = 0;
    virtual std::string getPathName() const = 0;
    virtual void setName(const std::string& name) = 0;
    virtual void setNameAndCategory(const CategoryPath& path, const std::string& name) = 0;
    virtual std::string getMnemonic(const std::shared_ptr<Settings>& settings) const = 0;
    virtual int getLength() const = 0;
    virtual int getAlignedLength() const = 0;
    virtual bool isZeroLength() const = 0;
    virtual bool isNotYetDefined() const = 0;
    virtual std::string getDescription() const = 0;
    virtual void setDescription(const std::string& description) = 0;
    virtual void* getValue(const std::shared_ptr<MemBuffer>& buf, const std::shared_ptr<Settings>& settings, int length) = 0;
    virtual bool isEncodable() const = 0;
    virtual std::vector<uint8_t> encodeValue(void* value, const std::shared_ptr<MemBuffer>& buf, const std::shared_ptr<Settings>& settings, int length) = 0;
    virtual std::string getValueClass(const std::shared_ptr<Settings>& settings) const = 0;
    virtual std::string getDefaultLabelPrefix() const = 0;
    virtual std::string getDefaultAbbreviatedLabelPrefix() const = 0;
    virtual std::string getRepresentation(const std::shared_ptr<MemBuffer>& buf, const std::shared_ptr<Settings>& settings, int length) = 0;
    virtual std::vector<uint8_t> encodeRepresentation(const std::string& repr, const std::shared_ptr<MemBuffer>& buf, const std::shared_ptr<Settings>& settings, int length) = 0;
    virtual bool isDeleted() const = 0;
    virtual bool isEquivalent(const std::shared_ptr<DataType>& dt) const = 0;
    virtual void dataTypeSizeChanged(const std::shared_ptr<DataType>& dt) = 0;
    virtual void dataTypeAlignmentChanged(const std::shared_ptr<DataType>& dt) = 0;
    virtual void dataTypeDeleted(const std::shared_ptr<DataType>& dt) = 0;
    virtual void dataTypeReplaced(const std::shared_ptr<DataType>& oldDt, const std::shared_ptr<DataType>& newDt) = 0;
    virtual void addParent(const std::shared_ptr<DataType>& dt) = 0;
    virtual void removeParent(const std::shared_ptr<DataType>& dt) = 0;
    virtual void dataTypeNameChanged(const std::shared_ptr<DataType>& dt, const std::string& oldName) = 0;
    virtual std::vector<std::shared_ptr<DataType>> getParents() const = 0;
    virtual int getAlignment() const = 0;
    virtual bool dependsOn(const std::shared_ptr<DataType>& dt) const = 0;
    virtual std::shared_ptr<SourceArchive> getSourceArchive() const = 0;
    virtual void setSourceArchive(const std::shared_ptr<SourceArchive>& archive) = 0;
    virtual int64_t getLastChangeTime() const = 0;
    virtual int64_t getLastChangeTimeInSourceArchive() const = 0;
    virtual uint64_t getUniversalID() const = 0;
    virtual void replaceWith(const std::shared_ptr<DataType>& dataType) = 0;
    virtual void setLastChangeTime(int64_t lastChangeTime) = 0;
    virtual void setLastChangeTimeInSourceArchive(int64_t lastChangeTimeInSourceArchive) = 0;
    virtual std::shared_ptr<DataOrganization> getDataOrganization() const = 0;
};

} // namespace ghidra
