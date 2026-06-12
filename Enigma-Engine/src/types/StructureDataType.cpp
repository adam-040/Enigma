/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra\StructureDataType.h>

namespace ghidra {

StructureDataType::StructureDataType(const std::string& name, int length, DataTypeManager* dtm)
    : StructureDataType(CategoryPath::ROOT(), name, length, dtm) {}

StructureDataType::StructureDataType(const CategoryPath& path, const std::string& name, int length, DataTypeManager* dtm)
    : CompositeDataTypeImpl(path, name, dtm), structLength_(length), numComponents_(length) {
    if (length < 0) throw std::invalid_argument("Length can't be negative");
}

StructureDataType::~StructureDataType() {
    for (auto c : components_) delete c;
}

int StructureDataType::getNumComponents() const { return numComponents_; }
int StructureDataType::getNumDefinedComponents() const { return static_cast<int>(components_.size()); }

DataTypeComponent* StructureDataType::getComponent(int ordinal) const {
    for (auto c : components_) {
        if (c->getOrdinal() == ordinal) return c;
    }
    return nullptr;
}

std::vector<DataTypeComponent*> StructureDataType::getComponents() const {
    return std::vector<DataTypeComponent*>(components_.begin(), components_.end());
}

std::vector<DataTypeComponent*> StructureDataType::getDefinedComponents() const {
    return getComponents();
}

DataTypeComponent* StructureDataType::add(DataType* dataType) {
    return add(dataType, 0, "", "");
}

DataTypeComponent* StructureDataType::add(DataType* dataType, int length) {
    return add(dataType, length, "", "");
}

DataTypeComponent* StructureDataType::add(DataType* dataType, const std::string& componentName, const std::string& comment) {
    return add(dataType, 0, componentName, comment);
}

DataTypeComponent* StructureDataType::add(DataType* dataType, int length, const std::string& componentName, const std::string& comment) {
    if (!dataType) throw std::invalid_argument("DataType must not be null");
    int compLength = getPreferredComponentLength(dataType, length);

    int offset = structLength_;
    auto* dtc = new DataTypeComponentImpl(dataType, compLength, numComponents_, offset, componentName, comment);
    components_.push_back(dtc);
    numComponents_++;
    structLength_ += compLength;
    return dtc;
}

DataTypeComponent* StructureDataType::insert(int ordinal, DataType* dataType) {
    return insert(ordinal, dataType, 0, "", "");
}

DataTypeComponent* StructureDataType::insert(int ordinal, DataType* dataType, int length) {
    return insert(ordinal, dataType, length, "", "");
}

DataTypeComponent* StructureDataType::insert(int ordinal, DataType* dataType, int length, const std::string& name, const std::string& comment) {
    if (!dataType) throw std::invalid_argument("DataType must not be null");
    int compLength = getPreferredComponentLength(dataType, length);

    int insertIdx = 0;
    for (size_t i = 0; i < components_.size(); i++) {
        if (components_[i]->getOrdinal() >= ordinal) break;
        insertIdx = static_cast<int>(i) + 1;
    }

    int offset = (insertIdx > 0) ? (components_[insertIdx - 1]->getOffset() + components_[insertIdx - 1]->getLength()) : 0;
    auto* dtc = new DataTypeComponentImpl(dataType, compLength, ordinal, offset, name, comment);
    components_.insert(components_.begin() + insertIdx, dtc);

    for (size_t i = insertIdx + 1; i < components_.size(); i++) {
        components_[i]->setOffset(components_[i]->getOffset() + compLength);
        components_[i]->setOrdinal(components_[i]->getOrdinal() + 1);
    }
    numComponents_++;
    structLength_ += compLength;
    return dtc;
}

void StructureDataType::deleteComponent(int ordinal) {
    for (size_t i = 0; i < components_.size(); i++) {
        if (components_[i]->getOrdinal() == ordinal) {
            int len = components_[i]->getLength();
            delete components_[i];
            components_.erase(components_.begin() + i);
            for (size_t j = i; j < components_.size(); j++) {
                components_[j]->setOffset(components_[j]->getOffset() - len);
                components_[j]->setOrdinal(components_[j]->getOrdinal() - 1);
            }
            numComponents_--;
            structLength_ -= len;
            return;
        }
    }
}

void StructureDataType::deleteComponents(const std::set<int>& ordinals) {
    for (auto it = ordinals.rbegin(); it != ordinals.rend(); ++it) {
        deleteComponent(*it);
    }
}

bool StructureDataType::isZeroLength() const { return structLength_ == 0; }

int StructureDataType::getLength() const {
    if (structLength_ == 0) return 1;
    return structLength_;
}

bool StructureDataType::hasLanguageDependantLength() const { return false; }

std::string StructureDataType::getRepresentation(MemBuffer*, Settings*, int) const {
    if (isNotYetDefined()) return "<Empty-Structure>";
    return "";
}

std::string StructureDataType::getDefaultLabelPrefix() const { return getName(); }

Structure* StructureDataType::clone(DataTypeManager* dtm) const {
    if (getDataTypeManager() == dtm) return const_cast<StructureDataType*>(this);
    auto* s = new StructureDataType(getCategoryPath(), getName(), 0, dtm);
    s->setDescription(getDescription());
    for (auto c : components_) {
        DataType* clonedDataType = c->getDataType()->clone(dtm);
        auto* added = static_cast<DataTypeComponentImpl*>(
            s->add(clonedDataType, c->getLength(), c->getFieldName(), c->getComment()));
        added->setOwnsDataType(clonedDataType != c->getDataType());
    }
    return s;
}

DataType* StructureDataType::copy(DataTypeManager* dtm) const { return clone(dtm); }

DataTypeComponent* StructureDataType::getDefinedComponentAtOrAfterOffset(int offset) const {
    for (auto c : components_) {
        if (c->getOffset() >= offset) return c;
    }
    return nullptr;
}

DataTypeComponent* StructureDataType::getComponentContaining(int offset) const {
    for (auto c : components_) {
        if (c->getOffset() <= offset && offset <= c->getEndOffset()) return c;
    }
    return nullptr;
}

std::vector<DataTypeComponent*> StructureDataType::getComponentsContaining(int offset) const {
    std::vector<DataTypeComponent*> result;
    for (auto c : components_) {
        if (c->getOffset() <= offset && offset <= c->getEndOffset()) result.push_back(c);
    }
    return result;
}

DataTypeComponent* StructureDataType::getDataTypeAt(int offset) const {
    return getComponentContaining(offset);
}

DataTypeComponent* StructureDataType::insertBitField(int ordinal, int byteWidth, int bitOffset, DataType* baseDataType, int bitSize, const std::string& componentName, const std::string& comment) {
    auto* bitField = new BitFieldDataType(baseDataType, bitSize, bitOffset);
    int componentLength = byteWidth > 0 ? byteWidth : bitField->getStorageSize();
    DataTypeComponent* component =
        insert(ordinal, bitField, componentLength, componentName, comment);
    if (auto* concrete = dynamic_cast<DataTypeComponentImpl*>(component)) {
        concrete->setOwnsDataType(true);
    }
    return component;
}

DataTypeComponent* StructureDataType::insertBitFieldAt(int byteOffset, int byteWidth, int bitOffset, DataType* baseDataType, int bitSize, const std::string& componentName, const std::string& comment) {
    auto* bitField = new BitFieldDataType(baseDataType, bitSize, bitOffset);
    int componentLength = byteWidth > 0 ? byteWidth : bitField->getStorageSize();

    for (size_t i = 0; i < components_.size(); ++i) {
        if (components_[i]->getOffset() != byteOffset) {
            continue;
        }

        if (!components_[i]->isBitFieldComponent()) {
            break;
        }

        int ordinal = components_[i]->getOrdinal();
        size_t insertIdx = i;
        while (insertIdx < components_.size() &&
               components_[insertIdx]->getOffset() == byteOffset &&
               components_[insertIdx]->isBitFieldComponent()) {
            ++insertIdx;
            ++ordinal;
        }

        auto* dtc = new DataTypeComponentImpl(bitField, componentLength, ordinal, byteOffset,
                                              componentName, comment, nullptr, true);
        components_.insert(components_.begin() + insertIdx, dtc);
        for (size_t j = insertIdx + 1; j < components_.size(); ++j) {
            components_[j]->setOrdinal(components_[j]->getOrdinal() + 1);
        }
        numComponents_++;
        structLength_ = std::max(structLength_, byteOffset + componentLength);
        return dtc;
    }

    DataTypeComponent* component =
        insertAtOffset(byteOffset, bitField, componentLength, componentName, comment);
    if (auto* concrete = dynamic_cast<DataTypeComponentImpl*>(component)) {
        concrete->setOwnsDataType(true);
    }
    return component;
}

DataTypeComponent* StructureDataType::insertAtOffset(int offset, DataType* dataType, int length) {
    return insertAtOffset(offset, dataType, length, "", "");
}

DataTypeComponent* StructureDataType::insertAtOffset(int offset, DataType* dataType, int length, const std::string& componentName, const std::string& comment) {
    if (!dataType) throw std::invalid_argument("DataType must not be null");
    int compLength = getPreferredComponentLength(dataType, length);

    int insertIdx = 0;
    for (size_t i = 0; i < components_.size(); i++) {
        if (components_[i]->getOffset() >= offset) break;
        insertIdx = static_cast<int>(i) + 1;
    }

    int ordinal = (insertIdx > 0) ? components_[insertIdx - 1]->getOrdinal() + 1 : 0;
    auto* dtc = new DataTypeComponentImpl(dataType, compLength, ordinal, offset, componentName, comment);
    components_.insert(components_.begin() + insertIdx, dtc);

    for (size_t i = insertIdx + 1; i < components_.size(); i++) {
        components_[i]->setOffset(components_[i]->getOffset() + compLength);
        components_[i]->setOrdinal(components_[i]->getOrdinal() + 1);
    }
    numComponents_++;
    structLength_ += compLength;
    return dtc;
}

void StructureDataType::deleteAtOffset(int offset) {
    for (size_t i = 0; i < components_.size(); i++) {
        if (components_[i]->getOffset() == offset) {
            deleteComponent(components_[i]->getOrdinal());
            return;
        }
    }
}

void StructureDataType::deleteAll() {
    for (auto c : components_) delete c;
    components_.clear();
    structLength_ = 0;
    numComponents_ = 0;
}

void StructureDataType::clearAtOffset(int offset) { deleteAtOffset(offset); }
void StructureDataType::clearComponent(int ordinal) { deleteComponent(ordinal); }

DataTypeComponent* StructureDataType::replace(int ordinal, DataType* dataType, int length) {
    return replace(ordinal, dataType, length, "", "");
}

DataTypeComponent* StructureDataType::replace(int ordinal, DataType* dataType, int length, const std::string& name, const std::string& comment) {
    if (!dataType) throw std::invalid_argument("DataType must not be null");

    for (size_t i = 0; i < components_.size(); i++) {
        if (components_[i]->getOrdinal() != ordinal) continue;

        int compLength = getPreferredComponentLength(dataType, length);
        int oldLength = components_[i]->getLength();
        int delta = compLength - oldLength;
        int offset = components_[i]->getOffset();

        delete components_[i];
        components_[i] = new DataTypeComponentImpl(dataType, compLength, ordinal, offset, name, comment);

        if (delta != 0) {
            for (size_t j = i + 1; j < components_.size(); j++) {
                components_[j]->setOffset(components_[j]->getOffset() + delta);
            }
            structLength_ += delta;
        }
        return components_[i];
    }

    throw std::out_of_range("Component ordinal out of range");
}

DataTypeComponent* StructureDataType::replaceAtOffset(int offset, DataType* dataType, int length, const std::string& name, const std::string& comment) {
    deleteAtOffset(offset);
    return insertAtOffset(offset, dataType, length, name, comment);
}

void StructureDataType::growStructure(int amount) {
    if (amount > 0) {
        structLength_ += amount;
        numComponents_ += amount;
    }
}

void StructureDataType::setLength(int length) {
    if (length < 0) return;
    structLength_ = length;
}

void StructureDataType::repack() {
    if (components_.empty()) {
        structLength_ = 0;
        numComponents_ = 0;
        return;
    }

    DataOrganization* organization = getDataOrganization();
    BitFieldPacking* bitFieldPacking = organization ? organization->getBitFieldPacking() : nullptr;

    int currentOffset = 0;
    int pendingBitFieldOffset = -1;
    int pendingBitFieldGroupLength = 0;
    int pendingBitFieldBitsUsed = 0;
    int pendingBitFieldBaseBits = 0;
    int pendingBitFieldAlignment = 1;

    auto flushBitFieldGroup = [&]() {
        if (pendingBitFieldOffset >= 0) {
            currentOffset = pendingBitFieldOffset + pendingBitFieldGroupLength;
            pendingBitFieldOffset = -1;
            pendingBitFieldGroupLength = 0;
            pendingBitFieldBitsUsed = 0;
            pendingBitFieldBaseBits = 0;
            pendingBitFieldAlignment = 1;
        }
    };

    for (size_t i = 0; i < components_.size(); ++i) {
        auto* component = components_[i];
        component->setOrdinal(static_cast<int>(i));

        auto* bitField = dynamic_cast<BitFieldDataType*>(component->getDataType());
        if (!bitField) {
            flushBitFieldGroup();

            int alignment = std::max(1, component->getDataType()->getAlignment());
            if (getPackingType() == PackingType::EXPLICIT && packing_ > 0) {
                alignment = std::min(alignment, packing_);
            }
            currentOffset = alignTo(currentOffset, alignment);
            component->setOffset(currentOffset);
            currentOffset += component->getLength();
            continue;
        }

        int alignment = getBitFieldAlignment(bitField, bitFieldPacking);
        if (getPackingType() == PackingType::EXPLICIT && packing_ > 0) {
            alignment = std::min(alignment, packing_);
        }

        const int baseBits = std::max(8, bitField->getBaseTypeSize() * 8);
        const int bitSize = bitField->getBitSize();

        bool canPackWithPending = pendingBitFieldOffset >= 0 &&
                                  pendingBitFieldBaseBits == baseBits &&
                                  pendingBitFieldBitsUsed + bitSize <= pendingBitFieldBaseBits &&
                                  pendingBitFieldAlignment == alignment;

        if (!canPackWithPending) {
            flushBitFieldGroup();
            currentOffset = alignTo(currentOffset, alignment);
            pendingBitFieldOffset = currentOffset;
            pendingBitFieldAlignment = alignment;
            pendingBitFieldBaseBits = baseBits;
            pendingBitFieldBitsUsed = 0;
            pendingBitFieldGroupLength = 0;
        }

        int newBitOffset = pendingBitFieldBitsUsed;
        auto* replacement = new BitFieldDataType(bitField->getBaseDataType(),
                                                 bitField->getDeclaredBitSize(),
                                                 newBitOffset);
        component->replaceDataType(replacement, true);
        component->setOffset(pendingBitFieldOffset);
        component->setLength(replacement->getStorageSize());

        pendingBitFieldBitsUsed += bitSize;
        pendingBitFieldGroupLength = std::max(pendingBitFieldGroupLength, replacement->getStorageSize());
    }

    flushBitFieldGroup();
    structLength_ = currentOffset;
    numComponents_ = static_cast<int>(components_.size());
}

bool StructureDataType::isEquivalent(const DataType* dt) const {
    if (dt == this) return true;
    const Structure* s = dynamic_cast<const Structure*>(dt);
    if (!s) return false;
    if (getName() != s->getName()) return false;
    auto myComps = getDefinedComponents();
    auto otherComps = s->getDefinedComponents();
    if (myComps.size() != otherComps.size()) return false;
    for (size_t i = 0; i < myComps.size(); i++) {
        if (!myComps[i]->isEquivalent(otherComps[i])) return false;
    }
    return true;
}

} // namespace ghidra
