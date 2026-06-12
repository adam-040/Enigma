/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/StandAloneDataTypeManager.h>
#include <ghidra/DataOrganization.h>
#include <ghidra/Pointer.h>
#include <ghidra/DataTypeConflictHandler.h>
#include <ghidra/DataTypePath.h>
#include <algorithm>
#include <cctype>

namespace ghidra {

// ── CategoryImpl (private nested class) ──────────────────────────────────────

class StandAloneDataTypeManager::CategoryImpl : public Category {
    StandAloneDataTypeManager* dtm_;
    CategoryImpl* parent_;
    CategoryPath path_;
    std::string name_;
    long id_;
    std::unordered_map<std::string, CategoryImpl*> subCategories_;
    std::unordered_map<std::string, DataType*> dataTypes_;
    mutable long nextSubCategoryId_;

public:
    CategoryImpl(StandAloneDataTypeManager* dtm, CategoryImpl* parent,
                 const std::string& name, long id)
        : dtm_(dtm), parent_(parent),
          path_(parent ? CategoryPath(parent->path_, name) : CategoryPath::ROOT()),
          name_(name), id_(id), nextSubCategoryId_(id * 1000 + 1) {}

    std::string getName() override { return name_; }
    void setName(const std::string& name) override { name_ = name; }

    std::vector<Category*> getCategories() override {
        std::vector<Category*> result;
        for (auto& [_, cat] : subCategories_)
            result.push_back(cat);
        return result;
    }

    std::vector<DataType*> getDataTypes() override {
        std::vector<DataType*> result;
        for (auto& [_, dt] : dataTypes_)
            result.push_back(dt);
        return result;
    }

    std::vector<DataType*> getDataTypesByBaseName(const std::string& name) override {
        std::vector<DataType*> result;
        for (auto& [n, dt] : dataTypes_)
            if (n == name)
                result.push_back(dt);
        return result;
    }

    DataType* addDataType(DataType* dt, DataTypeConflictHandler* handler) override {
        return dtm_->addDataType(dt, handler);
    }

    Category* getCategory(const std::string& name) override {
        auto it = subCategories_.find(name);
        return it != subCategories_.end() ? it->second : nullptr;
    }

    CategoryPath getCategoryPath() override { return path_; }

    DataType* getDataType(const std::string& name) override {
        auto it = dataTypes_.find(name);
        return it != dataTypes_.end() ? it->second : nullptr;
    }

    Category* createCategory(const std::string& name) override {
        auto it = subCategories_.find(name);
        if (it != subCategories_.end())
            return it->second;
        long newId = nextSubCategoryId_++;
        auto* cat = new CategoryImpl(dtm_, this, name, newId);
        subCategories_[name] = cat;
        dtm_->categoryById_[newId] = cat;
        dtm_->categoryByPath_[cat->path_.getPath()] = cat;
        return cat;
    }

    bool removeCategory(const std::string& name) override {
        auto it = subCategories_.find(name);
        if (it == subCategories_.end()) return false;
        dtm_->categoryById_.erase(it->second->id_);
        dtm_->categoryByPath_.erase(it->second->path_.getPath());
        delete it->second;
        subCategories_.erase(it);
        return true;
    }

    bool removeEmptyCategory(const std::string& name) override {
        auto it = subCategories_.find(name);
        if (it == subCategories_.end()) return false;
        if (!it->second->dataTypes_.empty()) return false;
        dtm_->categoryById_.erase(it->second->id_);
        dtm_->categoryByPath_.erase(it->second->path_.getPath());
        delete it->second;
        subCategories_.erase(it);
        return true;
    }

    void moveCategory(Category* /*category*/) override {}

    Category* copyCategory(Category* category, DataTypeConflictHandler* handler) override {
        if (!category) return nullptr;
        std::string n = category->getName();
        Category* newCat = createCategory(n);
        for (auto* dt : category->getDataTypes())
            newCat->addDataType(dt, handler);
        for (auto* sub : category->getCategories())
            newCat->copyCategory(sub, handler);
        return newCat;
    }

    Category* getParent() override { return parent_; }
    bool isRoot() override { return parent_ == nullptr; }
    std::string getCategoryPathName() override { return path_.getPath(); }
    Category* getRoot() override {
        CategoryImpl* r = this;
        while (r->parent_) r = r->parent_;
        return r;
    }

    DataTypeManager* getDataTypeManager() override { return dtm_; }

    void moveDataType(DataType* type, DataTypeConflictHandler* handler) override {
        dtm_->resolve(type, handler);
    }

    bool removeDataType(DataType* type) override {
        for (auto it = dataTypes_.begin(); it != dataTypes_.end(); ++it) {
            if (it->second == type) {
                dataTypes_.erase(it);
                return true;
            }
        }
        return false;
    }

    long getID() override { return id_; }

    void registerDataType(DataType* dt) {
        dataTypes_[dt->getName()] = dt;
    }

    bool hasDataType(const std::string& dtName) const {
        return dataTypes_.find(dtName) != dataTypes_.end();
    }

    void unregisterDataType(DataType* dt) {
        for (auto it = dataTypes_.begin(); it != dataTypes_.end(); ++it) {
            if (it->second == dt) {
                dataTypes_.erase(it);
                return;
            }
        }
    }

    long getNextSubCategoryId() const { return nextSubCategoryId_; }
    void setNextSubCategoryId(long id) { nextSubCategoryId_ = id; }
};

// ── StandAloneDataTypeManager implementation ─────────────────────────────────

StandAloneDataTypeManager::StandAloneDataTypeManager(const std::string& rootName)
    : name_(rootName),
      dataOrganization_(nullptr),
      ownsDataOrganization_(false),
      closed_(false),
      nextDataTypeId_(1),
      rootCategory_(nullptr),
      transactionCount_(0),
      transaction_(0),
      commitTransaction_(true) {
    rootCategory_ = new CategoryImpl(this, nullptr, rootName, 0);
    categoryById_[0] = rootCategory_;
    categoryByPath_[rootName] = rootCategory_;
}

StandAloneDataTypeManager::StandAloneDataTypeManager(const std::string& rootName,
        DataOrganization* dataOrganization)
    : name_(rootName),
      dataOrganization_(dataOrganization),
      ownsDataOrganization_(false),
      closed_(false),
      nextDataTypeId_(1),
      rootCategory_(nullptr),
      transactionCount_(0),
      transaction_(0),
      commitTransaction_(true) {
    rootCategory_ = new CategoryImpl(this, nullptr, rootName, 0);
    categoryById_[0] = rootCategory_;
    categoryByPath_[rootName] = rootCategory_;
}

StandAloneDataTypeManager::~StandAloneDataTypeManager() {
    close();
}

void StandAloneDataTypeManager::clear() {
    for (auto& [_, dt] : dataTypeById_) {
        CategoryPath catPath = dt->getCategoryPath();
        auto* cat = dynamic_cast<CategoryImpl*>(getCategory(catPath));
        if (cat) cat->unregisterDataType(dt);
    }
    dataTypeById_.clear();
    dataTypeByPath_.clear();
    dataTypeByName_.clear();
    dataTypeToId_.clear();

    if (rootCategory_) {
        for (auto& [_, cat] : categoryById_) {
            if (cat != rootCategory_) delete cat;
        }
        delete rootCategory_;
        rootCategory_ = nullptr;
    }
    categoryById_.clear();
    categoryByPath_.clear();
}

const std::string& StandAloneDataTypeManager::getName() const {
    return name_;
}

void StandAloneDataTypeManager::setName(const std::string& name) {
    name_ = name;
}

DataType* StandAloneDataTypeManager::getDataType(const CategoryPath& categoryPath,
        const std::string& name) {
    return findDataType(categoryPath, name);
}

DataType* StandAloneDataTypeManager::getDataType(long id) {
    auto it = dataTypeById_.find(id);
    return it != dataTypeById_.end() ? it->second : nullptr;
}

DataType* StandAloneDataTypeManager::getDataType(const std::string& dataTypePath) {
    for (auto& [_, dt] : dataTypeById_) {
        if (dt->getPathName() == dataTypePath)
            return dt;
    }
    return nullptr;
}

std::vector<DataType*> StandAloneDataTypeManager::getDataTypes() {
    std::vector<DataType*> result;
    result.reserve(dataTypeById_.size());
    for (auto& [_, dt] : dataTypeById_)
        result.push_back(dt);
    return result;
}

std::vector<std::string> StandAloneDataTypeManager::getDefinedCallingConventionNames() const {
    return {};
}

std::vector<std::string> StandAloneDataTypeManager::getKnownCallingConventionNames() const {
    return {};
}

DataOrganization* StandAloneDataTypeManager::getDataOrganization() const {
    return dataOrganization_;
}

long StandAloneDataTypeManager::getID(DataType* dt) {
    auto it = dataTypeToId_.find(dt);
    return it != dataTypeToId_.end() ? it->second : -1;
}

DataType* StandAloneDataTypeManager::resolve(DataType* dataType, DataTypeConflictHandler* handler) {
    if (!dataType) return nullptr;
    DataType* existing = findDataType(dataType->getCategoryPath(), dataType->getName());
    if (!existing) {
        return addDataType(dataType, handler);
    }
    if (handler) {
        auto result = handler->resolveConflict(dataType, existing);
        if (result == DataTypeConflictHandler::ConflictResult::USE_EXISTING)
            return existing;
        if (result == DataTypeConflictHandler::ConflictResult::REPLACE_EXISTING) {
            remove(existing);
            return addDataType(dataType, handler);
        }
    }
    CategoryPath catPath = dataType->getCategoryPath();
    std::string baseName = dataType->getName();
    std::string newName = baseName;
    int suffix = 1;
    while (findDataType(catPath, newName)) {
        newName = baseName + "." + std::to_string(suffix++);
    }
    if (dataType->getName() != newName)
        dataType->setName(newName);
    return addDataType(dataType, handler);
}

DataType* StandAloneDataTypeManager::addDataType(DataType* dataType,
        DataTypeConflictHandler* handler) {
    if (!dataType) return nullptr;
    DataType* existing = findDataType(dataType->getCategoryPath(), dataType->getName());
    if (existing) {
        if (handler) {
            auto result = handler->resolveConflict(dataType, existing);
            if (result == DataTypeConflictHandler::ConflictResult::USE_EXISTING)
                return existing;
            if (result == DataTypeConflictHandler::ConflictResult::REPLACE_EXISTING) {
                remove(existing);
            }
        }
    }
    long id = allocateDataTypeId();
    CategoryPath catPath = dataType->getCategoryPath();
    auto* cat = dynamic_cast<CategoryImpl*>(getCategory(catPath));
    if (!cat) {
        cat = dynamic_cast<CategoryImpl*>(createCategory(catPath));
    }
    dataTypeById_[id] = dataType;
    dataTypeToId_[dataType] = id;
    std::string pathKey = makePath(catPath, dataType->getName());
    dataTypeByPath_[pathKey] = dataType;
    dataTypeByName_[dataType->getName()].push_back(dataType);
    cat->registerDataType(dataType);
    return dataType;
}

DataType* StandAloneDataTypeManager::replaceDataType(DataType* existingDt,
        DataType* replacementDt, bool updateCategoryPath) {
    if (!existingDt || !replacementDt) return nullptr;
    CategoryPath catPath = existingDt->getCategoryPath();
    if (updateCategoryPath)
        replacementDt->setCategoryPath(catPath);
    remove(existingDt);
    return addDataType(replacementDt, nullptr);
}

void StandAloneDataTypeManager::findDataTypes(const std::string& name,
        std::vector<DataType*>& list) {
    findDataTypes(name, list, true);
}

void StandAloneDataTypeManager::findDataTypes(const std::string& name,
        std::vector<DataType*>& list, bool caseSensitive) {
    if (caseSensitive) {
        auto it = dataTypeByName_.find(name);
        if (it != dataTypeByName_.end())
            list.insert(list.end(), it->second.begin(), it->second.end());
    } else {
        std::string lowerName = name;
        for (auto& c : lowerName) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        for (auto& [storedName, dts] : dataTypeByName_) {
            std::string lowerStored = storedName;
            for (auto& c : lowerStored) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (lowerStored == lowerName)
                list.insert(list.end(), dts.begin(), dts.end());
        }
    }
}

Category* StandAloneDataTypeManager::getRootCategory() {
    return rootCategory_;
}

Category* StandAloneDataTypeManager::getCategory(const CategoryPath& path) {
    std::string pathStr = path.getPath();
    auto it = categoryByPath_.find(pathStr);
    if (it != categoryByPath_.end())
        return it->second;
    return rootCategory_;
}

Category* StandAloneDataTypeManager::getCategory(long categoryID) {
    auto it = categoryById_.find(categoryID);
    return it != categoryById_.end() ? it->second : nullptr;
}

Category* StandAloneDataTypeManager::createCategory(const CategoryPath& path) {
    auto it = categoryByPath_.find(path.getPath());
    if (it != categoryByPath_.end())
        return it->second;
    std::vector<std::string> names = path.asList();
    Category* current = rootCategory_;
    std::string accumulated;
    for (const auto& segment : names) {
        if (!accumulated.empty()) accumulated += "/";
        accumulated += segment;
        Category* child = current->getCategory(segment);
        if (!child) {
            child = current->createCategory(segment);
        }
        current = child;
    }
    return current;
}

int StandAloneDataTypeManager::getCategoryCount() const {
    return static_cast<int>(categoryById_.size());
}

bool StandAloneDataTypeManager::remove(DataType* dataType) {
    if (!dataType) return false;
    auto idIt = dataTypeToId_.find(dataType);
    if (idIt == dataTypeToId_.end()) return false;
    long id = idIt->second;
    CategoryPath catPath = dataType->getCategoryPath();
    std::string pathKey = makePath(catPath, dataType->getName());
    dataTypeById_.erase(id);
    dataTypeByPath_.erase(pathKey);
    dataTypeToId_.erase(dataType);
    auto nameIt = dataTypeByName_.find(dataType->getName());
    if (nameIt != dataTypeByName_.end()) {
        auto& vec = nameIt->second;
        vec.erase(std::remove(vec.begin(), vec.end(), dataType), vec.end());
        if (vec.empty()) dataTypeByName_.erase(nameIt);
    }
    auto* cat = dynamic_cast<CategoryImpl*>(getCategory(catPath));
    if (cat) cat->unregisterDataType(dataType);
    return true;
}

bool StandAloneDataTypeManager::contains(DataType* dataType) const {
    return dataTypeToId_.find(dataType) != dataTypeToId_.end();
}

bool StandAloneDataTypeManager::isUpdatable() const {
    return !closed_;
}

int StandAloneDataTypeManager::getDataTypeCount(bool includePointersAndArrays) const {
    (void)includePointersAndArrays;
    return static_cast<int>(dataTypeById_.size());
}

void StandAloneDataTypeManager::close() {
    if (closed_) return;
    closed_ = true;
    clear();
}

int StandAloneDataTypeManager::startTransaction(const std::string& description) {
    if (transactionCount_ == 0) {
        transaction_ = static_cast<long>(nextDataTypeId_);
        transactionName_ = description;
        commitTransaction_ = true;
    }
    transactionCount_++;
    return static_cast<int>(transaction_);
}

bool StandAloneDataTypeManager::endTransaction(int transactionID, bool commit) {
    (void)transactionID;
    if (!commit) commitTransaction_ = false;
    if (--transactionCount_ == 0) {
        if (transaction_ != 0) {
            redoList_.clear();
            undoList_.push_back(transactionName_);
            if (undoList_.size() > NUM_UNDOS)
                undoList_.pop_front();
        }
        transaction_ = 0;
        return true;
    }
    return transactionCount_ == 0;
}

UniversalID StandAloneDataTypeManager::getUniversalID() const {
    return UniversalID(static_cast<int64_t>(0));
}

ArchiveType StandAloneDataTypeManager::getType() const {
    return ArchiveType::TEMPORARY;
}

Pointer* StandAloneDataTypeManager::getPointer(DataType* datatype) {
    return getPointer(datatype, -1);
}

Pointer* StandAloneDataTypeManager::getPointer(DataType* datatype, int size) {
    if (!datatype) return nullptr;
    Pointer* existing = nullptr;
    for (auto& [_, dt] : dataTypeById_) {
        auto* ptr = dynamic_cast<Pointer*>(dt);
        if (ptr && ptr->getDataType() == datatype) {
            if (size <= 0 || ptr->getLength() == size) {
                existing = ptr;
                break;
            }
        }
    }
    return existing;
}

void StandAloneDataTypeManager::findEnumValueNames(long value,
        std::set<std::string>& enumValueNames) {
    (void)value;
    (void)enumValueNames;
}

bool StandAloneDataTypeManager::isFavorite(DataType* datatype) {
    (void)datatype;
    return false;
}

void StandAloneDataTypeManager::setFavorite(DataType* datatype, bool isFavorite) {
    (void)datatype;
    (void)isFavorite;
}

std::vector<DataType*> StandAloneDataTypeManager::getFavorites() {
    return {};
}

void StandAloneDataTypeManager::flushEvents() {}

long StandAloneDataTypeManager::allocateDataTypeId() {
    return nextDataTypeId_++;
}

std::string StandAloneDataTypeManager::makePath(const CategoryPath& categoryPath,
        const std::string& name) const {
    return categoryPath.getPath() + "/" + name;
}

DataType* StandAloneDataTypeManager::findDataType(const CategoryPath& categoryPath,
        const std::string& name) const {
    std::string pathKey = makePath(categoryPath, name);
    auto it = dataTypeByPath_.find(pathKey);
    return it != dataTypeByPath_.end() ? it->second : nullptr;
}

} // namespace ghidra
