/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ClassID.h
/// \brief Unique ID of a Program Class Type
/// Translated from: ghidra.program.model.gclass.ClassID
#pragma once

#include <string>
#include <functional>
#include <ghidra/CategoryPath.h>
#include <ghidra/SymbolPath.h>

namespace ghidra {

class ClassID {
public:
    ClassID(const CategoryPath& catPath, const SymbolPath& symPath)
        : categoryPath_(catPath), symbolPath_(symPath) {}

    const CategoryPath& getCategoryPath() const { return categoryPath_; }
    const SymbolPath& getSymbolPath() const { return symbolPath_; }
    std::string toString() const;
    int compareTo(const ClassID& other) const;
    int hashCode() const;
    bool operator==(const ClassID& other) const;
    bool operator!=(const ClassID& other) const { return !(*this == other); }

private:
    CategoryPath categoryPath_;
    SymbolPath symbolPath_;
};

} // namespace ghidra

namespace std {
    template<> struct hash<ghidra::ClassID> {
        std::size_t operator()(const ghidra::ClassID& id) const { return id.hashCode(); }
    };
}
