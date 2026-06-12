/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file TypeDef.h
/// \brief The typedef interface
#pragma once

#include "DataType.h"
#include "Pointer.h"

namespace ghidra {

/**
 * The typedef interface
 * Translated from: ghidra.program.model.data.TypeDef
 */
class TypeDef : public virtual DataType {
public:
    virtual ~TypeDef() = default;

    /**
     * Determine if this datatype use auto-naming
     * @return true if auto-named, else false.
     */
    virtual bool isAutoNamed() const = 0;

    /**
     * Enable auto-naming for this typedef.
     */
    virtual void enableAutoNaming() = 0;

    /**
     * Returns the dataType that this typedef is based on.
     * @return the datatype which this typedef is based on.
     */
    virtual DataType* getDataType() const = 0;

    /**
     * Returns the non-typedef dataType that this typedef is based on
     * @return the datatype which this typedef is based on.
     */
    virtual DataType* getBaseDataType() const = 0;

    /**
     * Determine if this is a Pointer-TypeDef
     * @return true if base datatype is a pointer
     */
    virtual bool isPointer() const {
        return dynamic_cast<Pointer*>(getBaseDataType()) != nullptr;
    }
};

} // namespace ghidra
