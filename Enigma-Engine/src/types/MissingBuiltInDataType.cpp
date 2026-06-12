/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/MissingBuiltInDataType.h>

namespace ghidra {

MissingBuiltInDataType::MissingBuiltInDataType(const CategoryPath& path,
        const std::string& missingBuiltInName,
        const std::string& missingBuiltInClassPath, DataTypeManager* dtm)
    : DataTypeImpl(path.getPath().empty() ? CategoryPath::ROOT() : path,
                   "-MISSING-" + missingBuiltInName, dtm),
      missingBuiltInName_(missingBuiltInName),
      missingBuiltInClassPath_(missingBuiltInClassPath) {}

std::string MissingBuiltInDataType::getMnemonic(Settings* settings) const {
    return getName();
}

int MissingBuiltInDataType::getLength() const {
    return -1;
}

bool MissingBuiltInDataType::canSpecifyLength() {
    return true;
}

int MissingBuiltInDataType::getLength(MemBuffer* buf, int maxLength) {
    return -1;
}

std::string MissingBuiltInDataType::getDescription() const {
    return "Missing Built-In Data Type: " + missingBuiltInClassPath_;
}

std::string MissingBuiltInDataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    return missingBuiltInClassPath_;
}

DataType* MissingBuiltInDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<MissingBuiltInDataType*>(this);
    }
    return new MissingBuiltInDataType(categoryPath_, missingBuiltInName_, missingBuiltInClassPath_, dtm);
}

DataType* MissingBuiltInDataType::copy(DataTypeManager* dtm) const {
    return clone(dtm);
}

bool MissingBuiltInDataType::isEquivalent(const DataType* dt) const {
    if (!dt) return false;
    if (dt == this) return true;
    auto* other = dynamic_cast<const MissingBuiltInDataType*>(dt);
    if (!other) return false;
    return missingBuiltInClassPath_ == other->missingBuiltInClassPath_;
}

int64_t MissingBuiltInDataType::getLastChangeTime() const {
    return 0;
}

DataType* MissingBuiltInDataType::getReplacementBaseType() {
    return nullptr;
}

void MissingBuiltInDataType::setDefaultSettings(Settings* settings) {}

std::string MissingBuiltInDataType::getCTypeDeclaration(DataOrganization* dataOrganization) {
    return "MissingBuiltInDataType";
}

} // namespace ghidra
