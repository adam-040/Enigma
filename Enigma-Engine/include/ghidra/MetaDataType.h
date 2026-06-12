/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once

#include <ghidra/DataType.h>

namespace ghidra {

class TypeDef;
class AbstractIntegerDataType;
class BooleanDataType;
class Pointer;
class Array;
class Structure;
class AbstractFloatDataType;
class ArrayStringable;
class FunctionDefinition;
class Enum;
class AbstractStringDataType;
class DefaultDataType;
class Undefined;

enum class MetaDataType {
    VOID,
    UNKNOWN,
    INT,
    UINT,
    BOOL,
    CODE,
    FLOAT,
    PTR,
    ARRAY,
    STRUCT
};

MetaDataType getMeta(DataType* dt);
DataType* getMostSpecificDataType(DataType* a, DataType* b);

} // namespace ghidra
