/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ClassUtils.h
/// \brief Utility class for Class-related software modeling
/// Translated from: ghidra.program.model.gclass.ClassUtils
#pragma once

#include <string>
#include <cstdint>
#include <ghidra/CategoryPath.h>
#include <ghidra/SymbolPath.h>

namespace ghidra {

class ClassID;
class Composite;
class DataType;
class DataTypeManager;

class ClassUtils {
public:
    static inline const std::string VTABLE = "vtable";
    static inline const std::string VBTABLE = "vbtable";
    static inline const std::string VFTABLE = "vftable";
    static inline const std::string VTPTR = "vtptr";
    static inline const std::string VBPTR = "vbptr";
    static inline const std::string VFPTR = "vfptr";

    static CategoryPath getClassPath(Composite* composite);
    static CategoryPath getClassPath(const ClassID& id);
    static CategoryPath getClassInternalsPath(const CategoryPath& path);
    static CategoryPath getClassInternalsPath(const CategoryPath& path, const std::string& className);
    static CategoryPath getClassInternalsPath(Composite* composite);
    static CategoryPath getClassInternalsPath(const ClassID& id);
    static bool isVTable(DataType* dt);
    static std::string createVxTableDescriptionOffsetTag(uint64_t offset);
    static uint64_t* validateVtableDescriptionOffsetTag(const std::string& tag);
    static int getVftEntrySize(DataTypeManager* dtm);
    static int getVbtEntrySize(DataTypeManager* dtm);

private:
    ClassUtils() = delete;

    static CategoryPath recurseGetCategoryPath(const CategoryPath& category, const SymbolPath& symbolPath);
};

} // namespace ghidra
