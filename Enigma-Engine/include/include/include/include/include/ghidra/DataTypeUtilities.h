/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataTypeUtilities.h
/// \brief Static utility functions for DataType names and conflict handling.
/// Translated from: ghidra.program.database.data.DataTypeUtilities
#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace ghidra {

class DataType;
class Array;
class BuiltIn;
class Pointer;
class DataTypeManager;
class CategoryPath;

/// Strip the conflict suffix (".conflict" or ".conflict<N>") from a name.
/// Pointer/array decorations are preserved on the stripped name.
std::string getNameWithoutConflict(const std::string& dataTypeName);

/// Strip the conflict suffix from a data type's name.
std::string getNameWithoutConflict(DataType* dt);

/// Get the trailing pointer and array decorations (e.g. " * * [10]") from
/// a name. Returns an empty string if there are no decorations.
std::string getPointerArrayDecorations(const std::string& dataTypeName);

/// Get the conflict value associated with a data type name.
/// Returns -1 if the name has no conflict suffix, 0 for ".conflict" without
/// a number, or the positive integer value for ".conflict<N>".
int getConflictValue(const std::string& dataTypeName);

/// Get the conflict value for a DataType instance.
int getConflictValue(DataType* dataType);

/// True if the given data type can have a conflict suffix in its name.
bool canHaveConflictName(DataType* dataType);

/// Get the base data type by stripping Pointer/Array/Typedef layers.
DataType* getBaseDataType(DataType* dt);

/// Get the base data type of an array, also walking pointers/typedefs.
DataType* getArrayBaseDataType(Array* arrayDt);

} // namespace ghidra
