/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/DataTypeInstance.h>
#include <ghidra/Dynamic.h>
#include <ghidra/FactoryDataType.h>
#include <ghidra/FunctionDefinition.h>
#include <ghidra/TypeDef.h>
#include <ghidra/PointerDataType.h>
#include <ghidra/MemBuffer.h>

namespace ghidra {

DataTypeInstance::DataTypeInstance(DataType* dt, int length)
    : dataType_(dt), length_(length) {
    if (length < 1) {
        length_ = (dt && dt->getLength() > 0) ? dt->getLength() : 1;
    }
}

std::string DataTypeInstance::toString() const {
    return dataType_ ? dataType_->getName() : "";
}

DataTypeInstance* DataTypeInstance::getDataTypeInstance(DataType* dataType, MemBuffer* buf,
        bool useAlignedLength) {
    return getDataTypeInstance(dataType, buf, -1, useAlignedLength);
}

DataTypeInstance* DataTypeInstance::getDataTypeInstance(DataType* dataType, int length,
        bool useAlignedLength) {
    if (!dataType) return nullptr;

    if (dynamic_cast<FactoryDataType*>(dataType)) return nullptr;

    bool isFunctionDef = dynamic_cast<FunctionDefinition*>(dataType) != nullptr;
    if (auto* td = dynamic_cast<TypeDef*>(dataType)) {
        isFunctionDef = dynamic_cast<FunctionDefinition*>(td->getBaseDataType()) != nullptr;
    }
    if (isFunctionDef) {
        dataType = new PointerDataType(dataType, -1, dataType->getDataTypeManager());
        length = dataType->getLength();
    }
    else if (auto* dyn = dynamic_cast<Dynamic*>(dataType)) {
        if (length <= 0 || !dyn->canSpecifyLength()) return nullptr;
    }
    else if (useAlignedLength) {
        length = dataType->getAlignedLength();
    }
    else {
        length = dataType->getLength();
    }

    if (length < 0) return nullptr;
    return new DataTypeInstance(dataType, length);
}

DataTypeInstance* DataTypeInstance::getDataTypeInstance(DataType* dataType, MemBuffer* buf,
        int length, bool useAlignedLength) {
    if (auto* factory = dynamic_cast<FactoryDataType*>(dataType)) {
        dataType = factory->getDataType(buf);
        length = -1;
    }

    if (!dataType) return nullptr;

    bool isFunctionDef = dynamic_cast<FunctionDefinition*>(dataType) != nullptr;
    if (auto* td = dynamic_cast<TypeDef*>(dataType)) {
        isFunctionDef = dynamic_cast<FunctionDefinition*>(td->getBaseDataType()) != nullptr;
    }
    if (isFunctionDef) {
        dataType = new PointerDataType(dataType, -1, dataType->getDataTypeManager());
        length = dataType->getLength();
    }
    else if (auto* dyn = dynamic_cast<Dynamic*>(dataType)) {
        length = dyn->getLength(buf, length);
    }
    else if (useAlignedLength) {
        length = dataType->getAlignedLength();
    }
    else {
        length = dataType->getLength();
    }

    if (length < 0) return nullptr;
    return new DataTypeInstance(dataType, length);
}

} // namespace ghidra
