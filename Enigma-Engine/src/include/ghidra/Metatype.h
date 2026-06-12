/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Metatype.h
/// \brief Data-type metatype classification helpers for protorules
/// Translated from: ghidra.program.model.pcode.PcodeDataTypeManager (getMetatype portion)
#pragma once

#include <ghidra/DataType.h>
#include <ghidra/TypeDef.h>
#include <ghidra/Pointer.h>
#include <ghidra/Array.h>
#include <ghidra/Structure.h>
#include <ghidra/Union.h>
#include <ghidra/AbstractFloatDataType.h>
#include <ghidra/AbstractIntegerDataType.h>
#include <ghidra/AbstractSignedIntegerDataType.h>
#include <ghidra/AbstractUnsignedIntegerDataType.h>
#include <ghidra/BooleanDataType.h>
#include <string>

namespace ghidra {

struct Metatype {
    static constexpr int TYPE_UNKNOWN = 15;
    static constexpr int TYPE_INT = 14;
    static constexpr int TYPE_UINT = 13;
    static constexpr int TYPE_BOOL = 12;
    static constexpr int TYPE_CODE = 11;
    static constexpr int TYPE_FLOAT = 10;
    static constexpr int TYPE_PTR = 9;
    static constexpr int TYPE_PTRREL = 8;
    static constexpr int TYPE_ARRAY = 7;
    static constexpr int TYPE_STRUCT = 4;
    static constexpr int TYPE_UNION = 3;

    static int getMetatype(DataType* dt) {
        if (auto* td = dynamic_cast<TypeDef*>(dt)) {
            dt = td->getBaseDataType();
        }
        if (dynamic_cast<AbstractFloatDataType*>(dt)) return TYPE_FLOAT;
        if (dynamic_cast<Pointer*>(dt)) return TYPE_PTR;
        if (dynamic_cast<Array*>(dt)) return TYPE_ARRAY;
        if (dynamic_cast<Structure*>(dt)) return TYPE_STRUCT;
        if (dynamic_cast<Union*>(dt)) return TYPE_UNION;
        if (dynamic_cast<BooleanDataType*>(dt)) return TYPE_BOOL;
        if (dynamic_cast<AbstractSignedIntegerDataType*>(dt)) return TYPE_INT;
        if (dynamic_cast<AbstractUnsignedIntegerDataType*>(dt)) return TYPE_UINT;
        return TYPE_UNKNOWN;
    }

    static std::string getMetatypeString(int meta) {
        switch (meta) {
            case TYPE_UNKNOWN: return "unknown";
            case TYPE_INT: return "int";
            case TYPE_UINT: return "uint";
            case TYPE_BOOL: return "bool";
            case TYPE_CODE: return "code";
            case TYPE_FLOAT: return "float";
            case TYPE_PTR: return "ptr";
            case TYPE_PTRREL: return "ptrrel";
            case TYPE_ARRAY: return "array";
            case TYPE_STRUCT: return "struct";
            case TYPE_UNION: return "union";
            default: return "unknown";
        }
    }

    static int getMetatypeFromString(const std::string& s) {
        if (s == "unknown") return TYPE_UNKNOWN;
        if (s == "int") return TYPE_INT;
        if (s == "uint") return TYPE_UINT;
        if (s == "bool") return TYPE_BOOL;
        if (s == "code") return TYPE_CODE;
        if (s == "float") return TYPE_FLOAT;
        if (s == "ptr") return TYPE_PTR;
        if (s == "ptrrel") return TYPE_PTRREL;
        if (s == "array") return TYPE_ARRAY;
        if (s == "struct") return TYPE_STRUCT;
        if (s == "union") return TYPE_UNION;
        return TYPE_UNKNOWN;
    }
};

} // namespace ghidra
