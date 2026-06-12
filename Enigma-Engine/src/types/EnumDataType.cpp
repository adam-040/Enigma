/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra\EnumDataType.h>

namespace ghidra {

EnumDataType::EnumDataType(const std::string& name, int length)
    : EnumDataType(CategoryPath::ROOT(), name, length, nullptr) {}

EnumDataType::EnumDataType(const CategoryPath& path, const std::string& name, int length, DataTypeManager* dtm)
    : GenericDataType(path, name, dtm), length_(length), signedState_(EnumSignedState::NONE) {
    if (length < 1 || length > 8) {
        throw std::invalid_argument("unsupported enum length");
    }
}

void EnumDataType::checkValue(long long value) const {
    if (length_ == 8) return;
    long long min = getMinPossibleValue();
    long long max = getMaxPossibleValue();
    if (value < min || value > max) {
        throw std::invalid_argument("Attempted to add a value outside the range for this enum");
    }
}

EnumSignedState EnumDataType::computeSignedness() const {
    if (valueMap_.empty()) return EnumSignedState::NONE;
    long long minValue = valueMap_.begin()->first;
    long long maxValue = valueMap_.rbegin()->first;

    if (maxValue > getMaxPossibleValue(length_, true)) {
        if (minValue < 0) return EnumSignedState::INVALID;
        return EnumSignedState::UNSIGNED;
    }
    if (minValue < 0) return EnumSignedState::SIGNED;
    return EnumSignedState::NONE;
}

long long EnumDataType::getMaxPossibleValue(int bytes, bool allowNegativeValues) const {
    if (bytes == 8) return 0x7FFFFFFFFFFFFFFFLL;
    int bits = bytes * 8;
    if (allowNegativeValues) bits -= 1;
    return (1ULL << bits) - 1;
}

long long EnumDataType::getMinPossibleValue(int bytes, bool allowNegativeValues) const {
    if (!allowNegativeValues) return 0;
    int bits = bytes * 8;
    return -(1ULL << (bits - 1));
}

long long EnumDataType::getValue(const std::string& name) const {
    auto it = nameMap_.find(name);
    if (it == nameMap_.end()) throw std::invalid_argument("No value for " + name);
    return it->second;
}

std::string EnumDataType::getName(long long value) const {
    auto it = valueMap_.find(value);
    if (it == valueMap_.end() || it->second.empty()) return "";
    return it->second.front();
}

std::vector<std::string> EnumDataType::getNames(long long value) const {
    auto it = valueMap_.find(value);
    if (it == valueMap_.end()) return {};
    return it->second;
}

std::string EnumDataType::getComment(const std::string& name) const {
    auto it = commentMap_.find(name);
    return it != commentMap_.end() ? it->second : "";
}

std::vector<long long> EnumDataType::getValues() const {
    std::vector<long long> values;
    for (const auto& kv : valueMap_) {
        values.push_back(kv.first);
    }
    return values;
}

std::vector<std::string> EnumDataType::getNames() const {
    std::vector<std::string> names;
    for (const auto& kv : valueMap_) {
        std::vector<std::string> list = kv.second;
        std::sort(list.begin(), list.end());
        names.insert(names.end(), list.begin(), list.end());
    }
    return names;
}

int EnumDataType::getCount() const {
    return nameMap_.size();
}

void EnumDataType::add(const std::string& name, long long value) {
    add(name, value, "");
}

void EnumDataType::add(const std::string& name, long long value, const std::string& comment) {
    checkValue(value);
    if (nameMap_.find(name) != nameMap_.end()) {
        throw std::invalid_argument("Already exists");
    }
    nameMap_[name] = value;
    valueMap_[value].push_back(name);
    if (!comment.empty()) {
        commentMap_[name] = comment;
    }
    signedState_ = computeSignedness();
}

void EnumDataType::remove(const std::string& name) {
    auto it = nameMap_.find(name);
    if (it == nameMap_.end()) return;
    long long value = it->second;
    nameMap_.erase(it);

    auto& list = valueMap_[value];
    list.erase(std::remove(list.begin(), list.end(), name), list.end());
    if (list.empty()) {
        valueMap_.erase(value);
    }
    commentMap_.erase(name);
    signedState_ = computeSignedness();
}

DataType* EnumDataType::copy(DataTypeManager* dtm) const {
    EnumDataType* newEnum = new EnumDataType(getCategoryPath(), getName(), getLength(), dtm);
    newEnum->setDescription(getDescription());
    for (const auto& name : getNames()) {
        newEnum->add(name, getValue(name), getComment(name));
    }
    return newEnum;
}

DataType* EnumDataType::clone(DataTypeManager* dtm) const {
    if (getDataTypeManager() == dtm) {
        return const_cast<EnumDataType*>(this);
    }
    return copy(dtm);
}

std::string EnumDataType::getMnemonic(Settings* /*settings*/) const {
    return name_;
}

int EnumDataType::getLength() const {
    return length_;
}

int EnumDataType::getAlignedLength() const {
    return length_;
}

bool EnumDataType::isSigned() const {
    return signedState_ == EnumSignedState::SIGNED;
}

EnumSignedState EnumDataType::getSignedState() const {
    return signedState_;
}

long long EnumDataType::getMinPossibleValue() const {
    return getMinPossibleValue(length_, signedState_ != EnumSignedState::UNSIGNED);
}

long long EnumDataType::getMaxPossibleValue() const {
    return getMaxPossibleValue(length_, signedState_ == EnumSignedState::SIGNED);
}

int EnumDataType::getMinimumPossibleLength() const {
    if (valueMap_.empty()) return 1;
    long long minValue = valueMap_.begin()->first;
    long long maxValue = valueMap_.rbegin()->first;
    bool hasNegativeValues = minValue < 0;

    for (int size = 1; size < 8; size *= 2) {
        long long minPossible = getMinPossibleValue(size, hasNegativeValues);
        long long maxPossible = getMaxPossibleValue(size, hasNegativeValues);
        if (minValue >= minPossible && maxValue <= maxPossible) {
            return size;
        }
    }
    return 8;
}

bool EnumDataType::contains(const std::string& name) const {
    return nameMap_.find(name) != nameMap_.end();
}

bool EnumDataType::contains(long long value) const {
    return valueMap_.find(value) != valueMap_.end();
}

bool EnumDataType::isEquivalent(const DataType* dt) const {
    if (dt == this) return true;
    const Enum* enumm = dynamic_cast<const Enum*>(dt);
    if (!enumm) return false;

    if (getName() != enumm->getName() || length_ != enumm->getLength() || getCount() != enumm->getCount()) {
        return false;
    }

    auto names = getNames();
    auto otherNames = enumm->getNames();
    if (names.size() != otherNames.size()) return false;

    for (size_t i = 0; i < names.size(); i++) {
        if (names[i] != otherNames[i]) return false;
        if (getValue(names[i]) != enumm->getValue(names[i])) return false;
        if (getComment(names[i]) != enumm->getComment(names[i])) return false;
    }
    return true;
}

const std::type_info& EnumDataType::getValueClass(Settings* /*settings*/) const {
    return typeid(long long);
}

std::string EnumDataType::getRepresentation(MemBuffer* /*buf*/, Settings* /*settings*/, int /*length*/) const {
    return "Enum";
}

} // namespace ghidra
