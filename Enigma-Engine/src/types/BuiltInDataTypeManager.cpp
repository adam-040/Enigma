/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/BuiltInDataTypeManager.h>
#include <ghidra/CategoryPath.h>
#include <ghidra/DataTypeConflictHandler.h>
#include <ghidra/IntegerDataType.h>
#include <ghidra/UnsignedIntegerDataType.h>
#include <ghidra/ShortDataType.h>
#include <ghidra/UnsignedShortDataType.h>
#include <ghidra/LongDataType.h>
#include <ghidra/UnsignedLongDataType.h>
#include <ghidra/LongLongDataType.h>
#include <ghidra/UnsignedLongLongDataType.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/UnsignedCharDataType.h>
#include <ghidra/CharDataType.h>
#include <ghidra/FloatDataType.h>
#include <ghidra/DoubleDataType.h>
#include <ghidra/LongDoubleDataType.h>
#include <ghidra/VoidDataType.h>
#include <ghidra/BooleanDataType.h>
#include <ghidra/WordDataType.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/QWordDataType.h>
#include <ghidra/Undefined.h>
#include <ghidra/PointerDataType.h>
#include <ghidra/StringDataType.h>
#include <ghidra/UnicodeDataType.h>
#include <ghidra/Unicode32DataType.h>
#include <stdexcept>

namespace ghidra {

BuiltInDataTypeManager* BuiltInDataTypeManager::manager_ = nullptr;

BuiltInDataTypeManager::BuiltInDataTypeManager()
    : StandAloneDataTypeManager(BUILT_IN_DATA_TYPES_NAME)
    , populated_(false)
{
    populateBuiltInTypes();
}

BuiltInDataTypeManager::~BuiltInDataTypeManager() = default;

BuiltInDataTypeManager& BuiltInDataTypeManager::getDataTypeManager() {
    if (!manager_) {
        manager_ = new BuiltInDataTypeManager();
    }
    return *manager_;
}

void BuiltInDataTypeManager::populateBuiltInTypes() {
    if (populated_) {
        return;
    }
    populated_ = true;

    int id = StandAloneDataTypeManager::startTransaction("Populate");

    auto registerType = [&](DataType* dt) {
        std::vector<DataType*> existing;
        findDataTypes(dt->getName(), existing);
        if (existing.empty()) {
            StandAloneDataTypeManager::addDataType(dt, nullptr);
        }
    };

    registerType(new IntegerDataType());
    registerType(new UnsignedIntegerDataType());
    registerType(new ShortDataType());
    registerType(new UnsignedShortDataType());
    registerType(new LongDataType());
    registerType(new UnsignedLongDataType());
    registerType(new LongLongDataType());
    registerType(new UnsignedLongLongDataType());
    registerType(new ByteDataType());
    registerType(new UnsignedCharDataType());
    registerType(new CharDataType());
    registerType(new FloatDataType());
    registerType(new DoubleDataType());
    registerType(new LongDoubleDataType());
    registerType(new VoidDataType());
    registerType(new BooleanDataType());
    registerType(new WordDataType());
    registerType(new DWordDataType());
    registerType(new QWordDataType());
    Undefined::getUndefinedDataType(1);
    registerType(new StringDataType());
    registerType(new UnicodeDataType());
    registerType(new Unicode32DataType());

    StandAloneDataTypeManager::endTransaction(id, true);
}

int BuiltInDataTypeManager::startTransaction(const std::string& description) {
    if (manager_) {
        throw std::runtime_error("Built-in datatype manager may not be modified");
    }
    return StandAloneDataTypeManager::startTransaction(description);
}

bool BuiltInDataTypeManager::endTransaction(int transactionID, bool commit) {
    if (manager_) {
        throw std::runtime_error("Built-in datatype manager may not be modified");
    }
    return StandAloneDataTypeManager::endTransaction(transactionID, commit);
}

bool BuiltInDataTypeManager::canUndo() const {
    return false;
}

bool BuiltInDataTypeManager::canRedo() const {
    return false;
}

Category* BuiltInDataTypeManager::createCategory(const CategoryPath& path) {
    if (path != CategoryPath::ROOT()) {
        throw std::runtime_error("Built-in category limited to root category only");
    }
    return StandAloneDataTypeManager::createCategory(path);
}

ArchiveType BuiltInDataTypeManager::getType() const {
    return ArchiveType::BUILT_IN;
}

DataType* BuiltInDataTypeManager::resolve(DataType* dataType, DataTypeConflictHandler* handler) {
    if (!dataType) return nullptr;
    DataType* existing = getDataType(CategoryPath::ROOT(), dataType->getName());
    if (existing) {
        return existing;
    }
    throw std::runtime_error("Cannot resolve unknown data types in built-in manager");
}

DataType* BuiltInDataTypeManager::addDataType(DataType* originalDataType,
                                              DataTypeConflictHandler* handler) {
    throw std::runtime_error("Cannot add data types to built-in manager");
}

void BuiltInDataTypeManager::setName(const std::string& name) {
    throw std::runtime_error("Cannot rename built-in datatype manager");
}

void BuiltInDataTypeManager::associateDataTypeWithArchive(DataType* datatype,
                                                          SourceArchive* archive) {
    throw std::runtime_error("Cannot associate archive with built-in datatype manager");
}

bool BuiltInDataTypeManager::remove(DataType* dataType) {
    throw std::runtime_error("Cannot remove from built-in datatype manager");
}

DataType* BuiltInDataTypeManager::replaceDataType(DataType* existingDt, DataType* replacementDt,
                                                   bool updateCategoryPath) {
    throw std::runtime_error("Cannot replace in built-in datatype manager");
}

void BuiltInDataTypeManager::close() {
}

} // namespace ghidra
