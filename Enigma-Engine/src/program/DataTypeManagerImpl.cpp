/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataTypeManagerImpl.cpp
/// \brief Concrete standard data type manager implementation
#include <ghidra/DataTypeManagerImpl.h>
#include <ghidra/Category.h>
#include <ghidra/VoidDataType.h>
#include <ghidra/BooleanDataType.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/SignedByteDataType.h>
#include <ghidra/ShortDataType.h>
#include <ghidra/IntegerDataType.h>
#include <ghidra/LongDataType.h>
#include <ghidra/LongLongDataType.h>
#include <ghidra/UnsignedShortDataType.h>
#include <ghidra/UnsignedIntegerDataType.h>
#include <ghidra/UnsignedLongDataType.h>
#include <ghidra/UnsignedLongLongDataType.h>
#include <ghidra/FloatDataType.h>
#include <ghidra/DoubleDataType.h>
#include <ghidra/LongDoubleDataType.h>
#include <ghidra/PointerDataType.h>
#include <ghidra/StringDataType.h>

namespace ghidra {

// Category tree node.  Mirrors StandAloneDataTypeManager's nested
// CategoryImpl but is owned/registered by DataTypeManagerImpl.  A nested
// class of DataTypeManagerImpl, so it must be defined at ghidra scope.
class DataTypeManagerImpl::CategoryImpl : public Category {
public:
    CategoryImpl(DataTypeManagerImpl* dtm, CategoryImpl* parent,
                 const std::string& name, long id)
        : dtm_(dtm), parent_(parent),
          path_(parent ? CategoryPath(parent->path_, name) : CategoryPath::ROOT()),
          name_(name), id_(id) {}

    std::string getName() override { return name_; }
    void setName(const std::string& name) override {
        dtm_->categoriesByPath_.erase(path_.getPath());
        name_ = name;
        path_ = parent_ ? CategoryPath(parent_->path_, name) : CategoryPath::ROOT();
        dtm_->categoriesByPath_[path_.getPath()] = this;
    }

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
        return dtm_->addDataType(dt);
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
        long newId = dtm_->nextCategoryId_++;
        auto* cat = new CategoryImpl(dtm_, this, name, newId);
        subCategories_[name] = cat;
        dtm_->categoriesById_[newId] = cat;
        dtm_->categoriesByPath_[cat->path_.getPath()] = cat;
        return cat;
    }

    bool removeCategory(const std::string& name) override {
        auto it = subCategories_.find(name);
        if (it == subCategories_.end()) return false;
        dtm_->categoriesById_.erase(it->second->id_);
        dtm_->categoriesByPath_.erase(it->second->path_.getPath());
        delete it->second;
        subCategories_.erase(it);
        return true;
    }

    bool removeEmptyCategory(const std::string& name) override {
        auto it = subCategories_.find(name);
        if (it == subCategories_.end()) return false;
        if (!it->second->dataTypes_.empty()) return false;
        dtm_->categoriesById_.erase(it->second->id_);
        dtm_->categoriesByPath_.erase(it->second->path_.getPath());
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

    void registerDataType(DataType* dt) { dataTypes_[dt->getName()] = dt; }

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

private:
    DataTypeManagerImpl* dtm_;
    CategoryImpl* parent_;
    CategoryPath path_;
    std::string name_;
    long id_;
    std::map<std::string, CategoryImpl*> subCategories_;
    std::map<std::string, DataType*> dataTypes_;
};

DataTypeManagerImpl::DataTypeManagerImpl() : DataTypeManagerImpl("ProgramDB") {}

DataTypeManagerImpl::DataTypeManagerImpl(const std::string& name) : name_(name) {
    dataOrganization_ = std::make_unique<DataOrganizationImpl>();
    rootCategory_ = new CategoryImpl(this, nullptr, "", 0);
    categoriesById_[0] = rootCategory_;
    categoriesByPath_["/"] = rootCategory_;
    populateBuiltInTypes();
}

DataTypeManagerImpl::~DataTypeManagerImpl() {
    // Category nodes are plain members of the manager's tree.
    delete rootCategory_;
    rootCategory_ = nullptr;
}

const std::string& DataTypeManagerImpl::getName() const {
    return name_;
}

DataType* DataTypeManagerImpl::getDataType(const CategoryPath& categoryPath, const std::string& name) {
    std::string key = categoryPath.getPath(name);
    auto it = typesByPath_.find(key);
    if (it != typesByPath_.end()) {
        return it->second;
    }
    return nullptr;
}

DataType* DataTypeManagerImpl::getDataType(int64_t id) {
    auto it = typesById_.find(id);
    if (it != typesById_.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<DataType*> DataTypeManagerImpl::getDataTypes() {
    std::vector<DataType*> result;
    result.reserve(types_.size());
    for (const auto& ptr : types_) {
        result.push_back(ptr.get());
    }
    return result;
}

int DataTypeManagerImpl::getDataTypeCount(bool includePointersAndArrays) const {
    (void)includePointersAndArrays;
    return static_cast<int>(typesById_.size());
}

DataOrganization* DataTypeManagerImpl::getDataOrganization() const {
    return dataOrganization_.get();
}

DataType* DataTypeManagerImpl::resolve(DataType* dataType, DataTypeConflictHandler* handler) {
    if (!dataType) return nullptr;
    // Check if type already exists by path
    std::string path = dataType->getCategoryPath().getPath(dataType->getName());
    auto it = typesByPath_.find(path);
    if (it != typesByPath_.end())
        return it->second;
    // Not found — add it
    return addDataType(dataType);
}

DataType* DataTypeManagerImpl::addDataType(DataType* dt) {
    if (!dt) return nullptr;

    // Check if already registered (exact same pointer)
    for (const auto& ptr : types_) {
        if (ptr.get() == dt) {
            return dt;
        }
    }
    // Also check adopted orphans: an orphan referenced by a variable must
    // not be re-adopted into types_ (that would double-own the object).
    for (const auto& ptr : orphans_) {
        if (ptr.get() == dt) {
            return dt;
        }
    }

    // Check if equivalent exists by path
    std::string key = dt->getCategoryPath().getPath(dt->getName());
    auto it = typesByPath_.find(key);
    if (it != typesByPath_.end()) {
        return it->second;
    }

    // Register
    types_.push_back(std::unique_ptr<DataType>(dt));
    int64_t id = getNextId();
    typesById_[id] = dt;
    typesByPath_[key] = dt;
    getOrCreateCategory(dt->getCategoryPath())->registerDataType(dt);
    return dt;
}

DataType* DataTypeManagerImpl::addDataTypeWithId(DataType* dt, int64_t id) {
    if (!dt) return nullptr;

    // Check if already registered (exact same pointer): record the extra id
    // (e.g. corpus builtin ids aliasing the engine's pre-registered types).
    for (const auto& ptr : types_) {
        if (ptr.get() == dt) {
            typesById_[id] = dt;
            if (id >= nextId_) {
                nextId_ = id + 1;
            }
            return dt;
        }
    }
    // See addDataType: adopted orphans must not be re-owned.
    for (const auto& ptr : orphans_) {
        if (ptr.get() == dt) {
            return dt;
        }
    }

    // Check if equivalent exists by path
    std::string key = dt->getCategoryPath().getPath(dt->getName());
    auto it = typesByPath_.find(key);
    if (it != typesByPath_.end()) {
        return it->second;
    }

    // Register with exact ID
    types_.push_back(std::unique_ptr<DataType>(dt));
    typesById_[id] = dt;
    typesByPath_[key] = dt;
    getOrCreateCategory(dt->getCategoryPath())->registerDataType(dt);

    if (id >= nextId_) {
        nextId_ = id + 1;
    }
    return dt;
}

void DataTypeManagerImpl::clearAllDataTypes() {
    types_.clear();
    typesById_.clear();
    typesByPath_.clear();
    nextId_ = 1000;
    populateBuiltInTypes();
}

void DataTypeManagerImpl::removeDataType(DataType* dt) {
    if (!dt) return;

    // Find ID and path keys
    int64_t idToDelete = -1;
    for (const auto& pair : typesById_) {
        if (pair.second == dt) {
            idToDelete = pair.first;
            break;
        }
    }

    std::string pathToDelete;
    for (const auto& pair : typesByPath_) {
        if (pair.second == dt) {
            pathToDelete = pair.first;
            break;
        }
    }

    if (idToDelete != -1) typesById_.erase(idToDelete);
    if (!pathToDelete.empty()) {
        typesByPath_.erase(pathToDelete);
        CategoryImpl* cat = getOrCreateCategory(dt->getCategoryPath());
        if (cat) {
            cat->unregisterDataType(dt);
        }
    }

    auto it = std::find_if(types_.begin(), types_.end(),
                           [dt](const std::unique_ptr<DataType>& p) { return p.get() == dt; });
    if (it != types_.end()) {
        types_.erase(it);
    }
}

int64_t DataTypeManagerImpl::getNextId() {
    return nextId_++;
}

void DataTypeManagerImpl::populateBuiltInTypes() {
    // Standard primitive types prepopulation
    auto addBuiltIn = [this](DataType* dt, long id) {
        types_.push_back(std::unique_ptr<DataType>(dt));
        typesById_[id] = dt;
        std::string key = dt->getCategoryPath().getPath(dt->getName());
        typesByPath_[key] = dt;
        rootCategory_->registerDataType(dt);
    };

    addBuiltIn(new VoidDataType(this), 1);
    addBuiltIn(new BooleanDataType(this), 2);
    addBuiltIn(new ByteDataType(this), 3);
    addBuiltIn(new SignedByteDataType(this), 4);
    addBuiltIn(new ShortDataType(this), 5);
    addBuiltIn(new IntegerDataType(this), 6);
    addBuiltIn(new LongDataType(this), 7);
    addBuiltIn(new LongLongDataType(this), 8);
    addBuiltIn(new UnsignedShortDataType(this), 9);
    addBuiltIn(new UnsignedIntegerDataType(this), 10);
    addBuiltIn(new UnsignedLongDataType(this), 11);
    addBuiltIn(new UnsignedLongLongDataType(this), 12);
    addBuiltIn(new FloatDataType(this), 13);
    addBuiltIn(new DoubleDataType(this), 14);
    addBuiltIn(new LongDoubleDataType(this), 15);
    addBuiltIn(new StringDataType(this), 16);
}

int64_t DataTypeManagerImpl::getDataTypeId(DataType* dt) const {
    if (!dt) return -1;
    for (const auto& pair : typesById_) {
        if (pair.second == dt) {
            return pair.first;
        }
    }
    return -1;
}

// ---------------------------------------------------------------------------
// Categories
// ---------------------------------------------------------------------------

Category* DataTypeManagerImpl::getRootCategory() {
    return rootCategory_;
}

Category* DataTypeManagerImpl::getCategory(const CategoryPath& path) {
    auto it = categoriesByPath_.find(path.getPath());
    return it != categoriesByPath_.end() ? it->second : nullptr;
}

Category* DataTypeManagerImpl::getCategory(long categoryID) {
    auto it = categoriesById_.find(categoryID);
    return it != categoriesById_.end() ? it->second : nullptr;
}

Category* DataTypeManagerImpl::createCategory(const CategoryPath& path) {
    return getOrCreateCategory(path);
}

int DataTypeManagerImpl::getCategoryCount() const {
    return static_cast<int>(categoriesById_.size());
}

DataTypeManagerImpl::CategoryImpl* DataTypeManagerImpl::getOrCreateCategory(
    const CategoryPath& path) {
    if (!rootCategory_) {
        return nullptr;
    }
    CategoryImpl* current = rootCategory_;
    const std::vector<std::string> names = path.asList();
    for (const std::string& segment : names) {
        Category* child = current->getCategory(segment);
        if (child) {
            current = static_cast<CategoryImpl*>(child);
        } else {
            current = static_cast<CategoryImpl*>(current->createCategory(segment));
        }
    }
    return current;
}

} // namespace ghidra
