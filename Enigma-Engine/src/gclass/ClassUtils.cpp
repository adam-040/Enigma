/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ClassUtils.cpp
/// \brief Class utility implementation
#include <ghidra/ClassUtils.h>
#include <ghidra/ClassID.h>
#include <ghidra/Composite.h>
#include <ghidra/DataType.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/DataOrganization.h>
#include <ghidra/SymbolPath.h>
#include <sstream>
#include <iomanip>

namespace ghidra {

CategoryPath ClassUtils::getClassPath(Composite* composite) {
    return CategoryPath(composite->getCategoryPath(), composite->getName());
}

CategoryPath ClassUtils::getClassPath(const ClassID& id) {
    return recurseGetCategoryPath(id.getCategoryPath(), id.getSymbolPath());
}

CategoryPath ClassUtils::getClassInternalsPath(const CategoryPath& path) {
    return path.extend("!internal");
}

CategoryPath ClassUtils::getClassInternalsPath(Composite* composite) {
    return getClassInternalsPath(composite->getCategoryPath(), composite->getName());
}

CategoryPath ClassUtils::getClassInternalsPath(const ClassID& id) {
    return getClassInternalsPath(getClassPath(id));
}

CategoryPath ClassUtils::getClassInternalsPath(const CategoryPath& path, const std::string& className) {
    return CategoryPath(CategoryPath(path, className), "!internal");
}

bool ClassUtils::isVTable(DataType* dt) {
    auto* composite = dynamic_cast<Composite*>(dt);
    if (!composite) return false;
    std::string description = composite->getDescription();
    return validateVtableDescriptionOffsetTag(description) != nullptr;
}

std::string ClassUtils::createVxTableDescriptionOffsetTag(uint64_t offset) {
    std::ostringstream oss;
    oss << "{{vtoffset 0x" << std::hex << std::setw(8) << std::setfill('0') << offset << "}}";
    return oss.str();
}

uint64_t* ClassUtils::validateVtableDescriptionOffsetTag(const std::string& tag) {
    static const std::string PREFIX = "{{vtoffset 0x";
    static const std::string SUFFIX = "}}";

    auto start = tag.find(PREFIX);
    if (start == std::string::npos) return nullptr;

    start += PREFIX.length();
    auto end = tag.find(SUFFIX, start);
    if (end == std::string::npos) return nullptr;

    std::string hexStr = tag.substr(start, end - start);
    if (hexStr.empty()) return nullptr;

    try {
        auto* result = new uint64_t(std::stoull(hexStr, nullptr, 16));
        return result;
    } catch (...) {
        return nullptr;
    }
}

int ClassUtils::getVftEntrySize(DataTypeManager* dtm) {
    auto* dataOrg = dtm->getDataOrganization();
    return dataOrg ? dataOrg->getPointerSize() : 0;
}

int ClassUtils::getVbtEntrySize(DataTypeManager* dtm) {
    auto* dataOrg = dtm->getDataOrganization();
    return dataOrg ? dataOrg->getIntegerSize() : 0;
}

CategoryPath ClassUtils::recurseGetCategoryPath(const CategoryPath& category, const SymbolPath& symbolPath) {
    auto* parent = symbolPath.getParent();
    CategoryPath cat = category;
    if (parent != nullptr) {
        cat = recurseGetCategoryPath(cat, *parent);
    }
    return CategoryPath(cat, symbolPath.getName());
}

} // namespace ghidra
