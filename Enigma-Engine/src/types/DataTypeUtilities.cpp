/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataTypeUtilities.cpp
#include "ghidra/DataTypeUtilities.h"

#include <ghidra/DataType.h>
#include <ghidra/BuiltIn.h>
#include <ghidra/BuiltInDataType.h>
#include <ghidra/Pointer.h>
#include <ghidra/Array.h>
#include <ghidra/TypeDef.h>
#include <regex>
#include <cctype>
#include <cstdlib>

namespace ghidra {

namespace {

bool isPointerOrArrayDecoration(char c) {
    return c == '*' || c == '[' || c == ']' || c == ' ';
}

int findDecorationStart(const std::string& s) {
    int firstStar = -1;
    int firstBracket = -1;
    for (int i = 0; i < static_cast<int>(s.size()); ++i) {
        char c = s[i];
        if (c == '*' && firstStar < 0) firstStar = i;
        if (c == '[' && firstBracket < 0) { firstBracket = i; break; }
    }
    if (firstStar < 0) return firstBracket;
    if (firstBracket < 0) return firstStar;
    return firstStar < firstBracket ? firstStar : firstBracket;
}

// Mirrors Java's BASE_DATATYPE_CONFLICT_PATTERN:
//   \.conflict([_]?[0-9]+)?$
// Matches ".conflict", ".conflict1", ".conflict_2", etc.
static const std::regex& conflictPattern() {
    static const std::regex re("\\.conflict([_]?[0-9]+)?$");
    return re;
}

bool endsWithConflict(const std::string& s, int* outNumber) {
    std::smatch m;
    if (!std::regex_search(s, m, conflictPattern())) {
        return false;
    }
    if (m.size() < 2 || !m[1].matched || m[1].str().empty()) {
        if (outNumber) *outNumber = 0;
        return true;
    }
    std::string numStr = m[1].str();
    if (numStr[0] == '_') numStr = numStr.substr(1);
    bool allDigits = true;
    for (char c : numStr) {
        if (!std::isdigit(static_cast<unsigned char>(c))) { allDigits = false; break; }
    }
    if (!allDigits) {
        if (outNumber) *outNumber = -1;
    } else {
        if (outNumber) *outNumber = std::atoi(numStr.c_str());
    }
    return true;
}

} // anonymous namespace

std::string getPointerArrayDecorations(const std::string& dataTypeName) {
    int idx = findDecorationStart(dataTypeName);
    if (idx < 0) return std::string();
    return dataTypeName.substr(idx);
}

std::string getNameWithoutConflict(const std::string& dataTypeName) {
    std::string decorations = getPointerArrayDecorations(dataTypeName);
    std::string baseName = dataTypeName;
    if (!decorations.empty()) {
        baseName = dataTypeName.substr(0, dataTypeName.size() - decorations.size());
    }
    int dummy;
    if (endsWithConflict(baseName, &dummy)) {
        std::string result = std::regex_replace(baseName, conflictPattern(), "");
        return result + decorations;
    }
    return baseName + decorations;
}

DataType* getBaseDataType(DataType* dt) {
    if (!dt) return nullptr;
    DataType* cur = dt;
    while (true) {
        if (auto* p = dynamic_cast<Pointer*>(cur)) {
            DataType* next = p->getDataType();
            if (!next) return cur;
            cur = next;
            continue;
        }
        if (auto* a = dynamic_cast<Array*>(cur)) {
            DataType* next = a->getDataType();
            if (!next) return cur;
            cur = next;
            continue;
        }
        if (auto* td = dynamic_cast<TypeDef*>(cur)) {
            DataType* next = td->getBaseDataType();
            if (!next) next = td->getDataType();
            if (!next) return cur;
            cur = next;
            continue;
        }
        return cur;
    }
}

DataType* getArrayBaseDataType(Array* arrayDt) {
    if (!arrayDt) return nullptr;
    DataType* cur = arrayDt->getDataType();
    return getBaseDataType(cur);
}

int getConflictValue(const std::string& dataTypeName) {
    std::string decorations = getPointerArrayDecorations(dataTypeName);
    std::string baseName = dataTypeName;
    if (!decorations.empty()) {
        baseName = dataTypeName.substr(0, dataTypeName.size() - decorations.size());
    }
    int number = -1;
    if (endsWithConflict(baseName, &number)) {
        return number;
    }
    return -1;
}

int getConflictValue(DataType* dataType) {
    if (!dataType) return -1;
    if (!canHaveConflictName(dataType)) return -1;
    DataType* baseDt = getBaseDataType(dataType);
    if (!baseDt) return -1;
    if (baseDt != dataType && !canHaveConflictName(baseDt)) return -1;
    return getConflictValue(baseDt->getName());
}

bool canHaveConflictName(DataType* dataType) {
    if (!dataType) return false;
    if (auto* p = dynamic_cast<Pointer*>(dataType)) {
        (void)p;
        return true;
    }
    if (dynamic_cast<BuiltIn*>(dataType)) {
        return false;
    }
    return true;
}

std::string getNameWithoutConflict(DataType* dt) {
    if (!dt) return std::string();
    if (!canHaveConflictName(dt)) return dt->getName();
    DataType* baseDt = getBaseDataType(dt);
    if (!baseDt) return dt->getName();
    if (baseDt != dt && !canHaveConflictName(baseDt)) return dt->getName();

    if (baseDt == dt) {
        return getNameWithoutConflict(dt->getName());
    }

    std::string baseDtName = baseDt->getName();
    std::string decorations = dt->getName().substr(baseDtName.size());
    return getNameWithoutConflict(baseDtName) + decorations;
}

} // namespace ghidra
