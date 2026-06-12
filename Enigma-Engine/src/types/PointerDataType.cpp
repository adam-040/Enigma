/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra\PointerDataType.h>

namespace ghidra {

std::string PointerDataType::constructUniqueName(DataType* referencedDataType, int ptrLength) {
    if (!referencedDataType) {
        std::string s = "pointer";
        if (ptrLength > 0) {
            s += std::to_string(8 * ptrLength);
        }
        return s;
    }
    std::string s = referencedDataType->getName() + " *";
    if (ptrLength > 0) {
        s += std::to_string(8 * ptrLength);
    }
    return s;
}

PointerDataType& PointerDataType::dataType() {
    static PointerDataType instance;
    return instance;
}

PointerDataType::PointerDataType(DataTypeManager* dtm)
    : PointerDataType(nullptr, -1, dtm) {}

PointerDataType::PointerDataType(DataType* referencedDataType, DataTypeManager* dtm)
    : PointerDataType(referencedDataType, -1, dtm) {}

PointerDataType::PointerDataType(DataType* referencedDataType, int length, DataTypeManager* dtm,
                bool ownsReferencedDataType)
    : BuiltIn(referencedDataType ? referencedDataType->getCategoryPath() : CategoryPath::ROOT(),
              constructUniqueName(referencedDataType, length), dtm),
      referencedDataType_(referencedDataType),
      length_(length <= 0 ? -1 : length),
      ownsReferencedDataType_(ownsReferencedDataType),
      deleted_(false) {
}

PointerDataType::~PointerDataType() {
    if (ownsReferencedDataType_) {
        delete referencedDataType_;
    }
}

DataType* PointerDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<PointerDataType*>(this);
    }
    DataType* clonedReferencedDataType =
        referencedDataType_ ? referencedDataType_->clone(dtm) : nullptr;
    return new PointerDataType(clonedReferencedDataType, length_, dtm,
                               clonedReferencedDataType && clonedReferencedDataType != referencedDataType_);
}

DataType* PointerDataType::getDataType() const {
    return referencedDataType_;
}

Pointer* PointerDataType::newPointer(DataType* dataType) const {
    return new PointerDataType(dataType, length_, getDataTypeManager());
}

bool PointerDataType::hasLanguageDependantLength() const {
    return length_ <= 0;
}

int PointerDataType::getLength() const {
    if (length_ > 0) {
        return length_;
    }
    DataOrganization* org = getDataOrganization();
    return org ? org->getPointerSize() : 8;
}

std::string PointerDataType::getDefaultLabelPrefix() const {
    return "PTR";
}

std::string PointerDataType::getDisplayName() const {
    if (displayName_.empty()) {
        if (!referencedDataType_) {
            displayName_ = "pointer";
            if (length_ > 0) {
                displayName_ += std::to_string(8 * length_);
            }
        } else {
            displayName_ = referencedDataType_->getDisplayName() + " *";
        }
    }
    return displayName_;
}

std::string PointerDataType::getDescription() const {
    std::string desc = "";
    if (length_ > 0) {
        desc += std::to_string(8 * length_) + "-bit ";
    }
    desc += "pointer";
    if (referencedDataType_) {
        desc += " to " + referencedDataType_->getDisplayName();
    }
    return desc;
}

std::string PointerDataType::getMnemonic(Settings* settings) const {
    if (!referencedDataType_) {
        return "addr";
    }
    return referencedDataType_->getMnemonic(settings) + " *";
}

std::string PointerDataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    return "??";
}

const std::type_info& PointerDataType::getValueClass(Settings* settings) const {
    return typeid(int64_t);
}

bool PointerDataType::isEquivalent(const DataType* dt) const {
    if (!dt) return false;
    if (this == dt) return true;
    const Pointer* p = dynamic_cast<const Pointer*>(dt);
    if (!p) return false;

    if (hasLanguageDependantLength() != p->hasLanguageDependantLength()) return false;
    if (!hasLanguageDependantLength() && (getLength() != p->getLength())) return false;

    DataType* otherDataType = p->getDataType();
    if (!referencedDataType_) return !otherDataType;
    if (!otherDataType) return false;

    return referencedDataType_->isEquivalent(otherDataType);
}

} // namespace ghidra
