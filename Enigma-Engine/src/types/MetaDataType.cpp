/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/MetaDataType.h>
#include <ghidra/TypeDef.h>
#include <ghidra/DefaultDataType.h>
#include <ghidra/Undefined.h>
#include <ghidra/AbstractIntegerDataType.h>
#include <ghidra/BooleanDataType.h>
#include <ghidra/Pointer.h>
#include <ghidra/Array.h>
#include <ghidra/Structure.h>
#include <ghidra/AbstractFloatDataType.h>
#include <ghidra/ArrayStringable.h>
#include <ghidra/FunctionDefinition.h>
#include <ghidra/Enum.h>
#include <ghidra/AbstractStringDataType.h>

namespace ghidra {

MetaDataType getMeta(DataType* dt) {
    if (!dt) return MetaDataType::STRUCT;
    if (dynamic_cast<TypeDef*>(dt)) {
        dt = dynamic_cast<TypeDef*>(dt)->getBaseDataType();
    }
    if (dynamic_cast<DefaultDataType*>(dt) || dynamic_cast<Undefined*>(dt)) {
        return MetaDataType::UNKNOWN;
    }
    if (dynamic_cast<AbstractIntegerDataType*>(dt)) {
        if (dynamic_cast<BooleanDataType*>(dt)) {
            return MetaDataType::BOOL;
        }
        if (dynamic_cast<AbstractIntegerDataType*>(dt)->isSigned()) {
            return MetaDataType::INT;
        }
        return MetaDataType::UINT;
    }
    if (dynamic_cast<Pointer*>(dt)) {
        return MetaDataType::PTR;
    }
    if (dynamic_cast<Array*>(dt)) {
        return MetaDataType::ARRAY;
    }
    if (dynamic_cast<Structure*>(dt)) {
        return MetaDataType::STRUCT;
    }
    if (dynamic_cast<AbstractFloatDataType*>(dt)) {
        return MetaDataType::FLOAT;
    }
    if (dynamic_cast<ArrayStringable*>(dt)) {
        return MetaDataType::INT;
    }
    if (dynamic_cast<FunctionDefinition*>(dt)) {
        return MetaDataType::CODE;
    }
    if (dynamic_cast<Enum*>(dt)) {
        return MetaDataType::UINT;
    }
    if (dynamic_cast<AbstractStringDataType*>(dt)) {
        return MetaDataType::ARRAY;
    }
    return MetaDataType::STRUCT;
}

DataType* getMostSpecificDataType(DataType* a, DataType* b) {
    DataType* aCopy = a;
    DataType* bCopy = b;
    for (;;) {
        if (!a) return bCopy;
        if (!b) return aCopy;
        MetaDataType aMeta = getMeta(a);
        MetaDataType bMeta = getMeta(b);
        int compare = static_cast<int>(aMeta) - static_cast<int>(bMeta);
        if (compare < 0) return bCopy;
        else if (compare > 0) return aCopy;
        if (aMeta == MetaDataType::PTR) {
            if (dynamic_cast<TypeDef*>(a)) a = dynamic_cast<TypeDef*>(a)->getBaseDataType();
            if (dynamic_cast<TypeDef*>(b)) b = dynamic_cast<TypeDef*>(b)->getBaseDataType();
            a = dynamic_cast<Pointer*>(a)->getDataType();
            b = dynamic_cast<Pointer*>(b)->getDataType();
        }
        else if (aMeta == MetaDataType::ARRAY) {
            if (dynamic_cast<TypeDef*>(a)) a = dynamic_cast<TypeDef*>(a)->getBaseDataType();
            if (dynamic_cast<TypeDef*>(b)) b = dynamic_cast<TypeDef*>(b)->getBaseDataType();
            if (!dynamic_cast<Array*>(a) || !dynamic_cast<Array*>(b)) break;
            a = dynamic_cast<Array*>(a)->getDataType();
            b = dynamic_cast<Array*>(b)->getDataType();
        }
        else {
            break;
        }
    }
    return aCopy;
}

} // namespace ghidra
