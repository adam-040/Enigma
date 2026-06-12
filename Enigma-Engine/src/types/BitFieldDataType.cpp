/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra\BitFieldDataType.h>

namespace ghidra {

int BitFieldDataType::getEffectiveBitSize(int declaredBitSize, int baseTypeByteSize) {
    return std::min(8 * baseTypeByteSize, declaredBitSize);
}

int BitFieldDataType::getMinimumStorageSize(int bitSize, int bitOffset) {
    if (bitSize == 0) return 1;
    return (bitSize + (bitOffset % 8) + 7) / 8;
}

bool BitFieldDataType::isValidBaseDataType(DataType* baseDataType) {
    if (!baseDataType) return false;
    if (auto* typeDef = dynamic_cast<TypeDef*>(baseDataType)) {
        baseDataType = typeDef->getBaseDataType();
    }
    return dynamic_cast<Enum*>(baseDataType) != nullptr ||
           dynamic_cast<AbstractIntegerDataType*>(baseDataType) != nullptr;
}

void BitFieldDataType::checkBaseDataType(DataType* baseDataType) {
    if (!isValidBaseDataType(baseDataType)) {
        throw std::invalid_argument("Unsupported base data type for bitfield");
    }
}

BitFieldDataType::BitFieldDataType(DataType* baseDataType, int bitSize, int bitOffset, bool ownsBaseDataType)
    : DataTypeImpl(CategoryPath::ROOT(),
                   (baseDataType ? baseDataType->getName() : std::string("bitfield")) + ":" +
                       std::to_string(bitSize),
                   baseDataType ? baseDataType->getDataTypeManager() : nullptr),
      baseDataType_(baseDataType),
      ownsBaseDataType_(ownsBaseDataType),
      declaredBitSize_(bitSize),
      effectiveBitSize_(0),
      bitOffset_(bitOffset),
      storageSize_(1) {
    if (!baseDataType_) {
        throw std::invalid_argument("BitField base data type may not be null");
    }
    checkBaseDataType(baseDataType_);
    if (bitSize < 0 || bitSize > MAX_BIT_LENGTH) {
        throw std::invalid_argument("unsupported bit size");
    }
    if (bitOffset < 0 || bitOffset > 7) {
        throw std::invalid_argument("unsupported minimal bit offset");
    }

    effectiveBitSize_ = getEffectiveBitSize(bitSize, baseDataType_->getLength());
    storageSize_ = getMinimumStorageSize(effectiveBitSize_, bitOffset_);
}

BitFieldDataType::~BitFieldDataType() {
    if (ownsBaseDataType_) {
        delete baseDataType_;
    }
}

bool BitFieldDataType::isZeroLength() const {
    return declaredBitSize_ == 0;
}

bool BitFieldDataType::hasLanguageDependantLength() const {
    return baseDataType_->hasLanguageDependantLength();
}

DataType* BitFieldDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<BitFieldDataType*>(this);
    }
    DataType* clonedBaseType = baseDataType_->clone(dtm);
    return new BitFieldDataType(clonedBaseType, declaredBitSize_, bitOffset_,
                                clonedBaseType != baseDataType_);
}

DataType* BitFieldDataType::copy(DataTypeManager* dtm) const {
    return clone(dtm);
}

int BitFieldDataType::getLength() const {
    return storageSize_;
}

int BitFieldDataType::getAlignedLength() const {
    return getLength();
}

std::string BitFieldDataType::getDescription() const {
    std::string description = std::to_string(effectiveBitSize_) + "-bit " +
                              baseDataType_->getDisplayName() + " bitfield";
    if (effectiveBitSize_ != declaredBitSize_) {
        description += " (declared as " + std::to_string(declaredBitSize_) + "-bits)";
    }
    return description;
}

std::string BitFieldDataType::getRepresentation(MemBuffer*, Settings*, int) const {
    return declaredBitSize_ == 0 ? "" : "??";
}

const std::type_info& BitFieldDataType::getValueClass(Settings*) const {
    return baseDataType_->getValueClass(nullptr);
}

bool BitFieldDataType::isEquivalent(const DataType* dt) const {
    if (dt == this) return true;
    auto* otherBitField = dynamic_cast<const BitFieldDataType*>(dt);
    if (!otherBitField) return false;
    return declaredBitSize_ == otherBitField->declaredBitSize_ &&
           baseDataType_->isEquivalent(otherBitField->baseDataType_);
}

int BitFieldDataType::getAlignment() const {
    return baseDataType_->getAlignment();
}

int BitFieldDataType::getBitSize() const {
    return effectiveBitSize_;
}

int BitFieldDataType::getDeclaredBitSize() const {
    return declaredBitSize_;
}

int BitFieldDataType::getBitOffset() const {
    return bitOffset_;
}

int BitFieldDataType::getStorageSize() const {
    return storageSize_;
}

int BitFieldDataType::getBaseTypeSize() const {
    return baseDataType_->getLength();
}

DataType* BitFieldDataType::getBaseDataType() const {
    return baseDataType_;
}

std::string BitFieldDataType::getDefaultLabelPrefix() const {
    return "BITFIELD";
}

} // namespace ghidra
