/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataTypeComponent.h
/// \brief Holder for datatypes that make up composite dataTypes (Structures/Unions).
#pragma once

#include <string>
#include <sstream>
#include <iomanip>
#include "DataType.h"
#include "ArrayDataType.h"
#include "TypedefDataType.h"

namespace ghidra {

class Settings;
class Structure; // Forward decl

/**
 * DataTypeComponents are holders for the dataTypes that make up composite (Structures
 * and Unions) dataTypes.
 * Translated from: ghidra.program.model.data.DataTypeComponent
 */
class DataTypeComponent {
public:
    static inline const std::string DEFAULT_FIELD_NAME_PREFIX = "field";

    virtual ~DataTypeComponent() = default;

    virtual DataType* getDataType() const = 0;

    virtual DataType* getParent() const = 0;

    virtual bool isBitFieldComponent() const = 0;

    virtual bool isZeroBitFieldComponent() const = 0;

    virtual int getOrdinal() const = 0;

    virtual int getOffset() const = 0;

    virtual int getEndOffset() const = 0;

    virtual int getLength() const = 0;

    virtual std::string getComment() const = 0;

    virtual Settings* getDefaultSettings() const = 0;

    // In C++ we can't easily return a modified clone of `this` if it's an abstract interface,
    // so we return DataTypeComponent*. The caller must take ownership or we return a new instance.
    virtual DataTypeComponent* setComment(const std::string& comment) = 0;

    virtual std::string getFieldName() const = 0;

    virtual DataTypeComponent* setFieldName(const std::string& fieldName) = 0;

    virtual std::string getDefaultFieldName() const {
        if (isZeroBitFieldComponent()) {
            return ""; // null in Java
        }
        std::string name = DEFAULT_FIELD_NAME_PREFIX + std::to_string(getOrdinal());
        // Since we can't easily RTTI check `instanceof Structure` without including Structure.h
        // We'll rely on subclasses to override this if they are in a structure.
        return name;
    }

    virtual bool isEquivalent(const DataTypeComponent* dtc) const = 0;

    static bool usesZeroLengthComponent(DataType* dataType) {
        if (!dataType) return false;
        // Only zero-length arrays (flexible-array members) and typedefs of
        // them are zero-length components; empty composites keep their
        // recorded member length (Ghidra semantics).
        if (auto* arr = dynamic_cast<ArrayDataType*>(dataType)) {
            return arr->isZeroLength();
        }
        if (auto* td = dynamic_cast<TypedefDataType*>(dataType)) {
            return usesZeroLengthComponent(td->getBaseDataType());
        }
        return false;
    }

    virtual bool isUndefined() const = 0;
};

} // namespace ghidra
