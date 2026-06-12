/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra\UnionDataType.h>

namespace ghidra {

UnionDataType::UnionDataType(const std::string& name, DataTypeManager* dtm)
    : UnionDataType(CategoryPath::ROOT(), name, dtm) {}

UnionDataType::UnionDataType(const CategoryPath& path, const std::string& name, DataTypeManager* dtm)
    : CompositeDataTypeImpl(path, name, dtm), unionLength_(0) {}

UnionDataType::~UnionDataType() {
    for (auto c : components_) delete c;
}

int UnionDataType::getNumComponents() const { return static_cast<int>(components_.size()); }
int UnionDataType::getNumDefinedComponents() const { return static_cast<int>(components_.size()); }

DataTypeComponent* UnionDataType::getComponent(int ordinal) const {
    if (ordinal < 0 || ordinal >= static_cast<int>(components_.size())) return nullptr;
    return components_[ordinal];
}

std::vector<DataTypeComponent*> UnionDataType::getComponents() const {
    return std::vector<DataTypeComponent*>(components_.begin(), components_.end());
}

std::vector<DataTypeComponent*> UnionDataType::getDefinedComponents() const {
    return getComponents();
}

DataTypeComponent* UnionDataType::add(DataType* dataType) {
    return add(dataType, 0, "", "");
}

DataTypeComponent* UnionDataType::add(DataType* dataType, int length) {
    return add(dataType, length, "", "");
}

DataTypeComponent* UnionDataType::add(DataType* dataType, const std::string& componentName, const std::string& comment) {
    return add(dataType, 0, componentName, comment);
}

DataTypeComponent* UnionDataType::add(DataType* dataType, int length, const std::string& componentName, const std::string& comment) {
    if (!dataType) throw std::invalid_argument("DataType must not be null");
    int compLength = getPreferredComponentLength(dataType, length);

    auto* dtc = new DataTypeComponentImpl(dataType, compLength,
        static_cast<int>(components_.size()), 0, componentName, comment);
    components_.push_back(dtc);
    if (compLength > unionLength_) unionLength_ = compLength;
    return dtc;
}

DataTypeComponent* UnionDataType::insert(int ordinal, DataType* dataType) {
    return insert(ordinal, dataType, 0, "", "");
}

DataTypeComponent* UnionDataType::insert(int ordinal, DataType* dataType, int length) {
    return insert(ordinal, dataType, length, "", "");
}

DataTypeComponent* UnionDataType::insert(int /*ordinal*/, DataType* dataType, int length, const std::string& name, const std::string& comment) {
    return add(dataType, length, name, comment);
}

void UnionDataType::deleteComponent(int ordinal) {
    if (ordinal < 0 || ordinal >= static_cast<int>(components_.size())) return;
    delete components_[ordinal];
    components_.erase(components_.begin() + ordinal);
    unionLength_ = 0;
    for (int i = 0; i < static_cast<int>(components_.size()); i++) {
        components_[i]->setOrdinal(i);
        if (components_[i]->getLength() > unionLength_)
            unionLength_ = components_[i]->getLength();
    }
}

void UnionDataType::deleteComponents(const std::set<int>& ordinals) {
    for (auto it = ordinals.rbegin(); it != ordinals.rend(); ++it) {
        deleteComponent(*it);
    }
}

bool UnionDataType::isZeroLength() const { return unionLength_ == 0; }

int UnionDataType::getLength() const {
    if (unionLength_ == 0) return 1;
    return unionLength_;
}

void UnionDataType::repack() {
    unionLength_ = 0;
    for (size_t i = 0; i < components_.size(); ++i) {
        components_[i]->setOrdinal(static_cast<int>(i));
        components_[i]->setOffset(0);
        if (components_[i]->getLength() > unionLength_) {
            unionLength_ = components_[i]->getLength();
        }
    }
}

bool UnionDataType::hasLanguageDependantLength() const { return true; }

std::string UnionDataType::getRepresentation(MemBuffer*, Settings*, int) const {
    if (isNotYetDefined()) return "<Empty-Union>";
    return "";
}

std::string UnionDataType::getDefaultLabelPrefix() const { return "UNION_" + getName(); }

DataType* UnionDataType::clone(DataTypeManager* dtm) const {
    if (getDataTypeManager() == dtm) return const_cast<UnionDataType*>(this);
    auto* u = new UnionDataType(getCategoryPath(), getName(), dtm);
    u->setDescription(getDescription());
    for (auto c : components_) {
        DataType* clonedDataType = c->getDataType()->clone(dtm);
        auto* added = static_cast<DataTypeComponentImpl*>(
            u->add(clonedDataType, c->getLength(), c->getFieldName(), c->getComment()));
        added->setOwnsDataType(clonedDataType != c->getDataType());
    }
    return u;
}

DataType* UnionDataType::copy(DataTypeManager* dtm) const { return clone(dtm); }

bool UnionDataType::isEquivalent(const DataType* dt) const {
    if (dt == this) return true;
    const Union* u = dynamic_cast<const Union*>(dt);
    if (!u) return false;
    if (getName() != u->getName()) return false;
    auto myComps = getComponents();
    auto otherComps = u->getComponents();
    if (myComps.size() != otherComps.size()) return false;
    for (size_t i = 0; i < myComps.size(); i++) {
        if (!myComps[i]->isEquivalent(otherComps[i])) return false;
    }
    return true;
}

} // namespace ghidra
