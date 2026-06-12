/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Array.h
/// \brief Array interface
#pragma once

#include "DataType.h"

namespace ghidra {

/**
 * Array interface
 * Translated from: ghidra.program.model.data.Array
 */
class Array : public virtual DataType {
public:
    static inline const std::string ARRAY_LABEL_PREFIX = "ARRAY";

    virtual ~Array() = default;

    /**
     * Returns the number of elements in the array
     * @return the number of elements in the array
     */
    virtual int getNumElements() const = 0;

    /**
     * Returns the length of an element in the array.
     * @return the length of one element in the array.
     */
    virtual int getElementLength() const = 0;

    /**
     * Returns the dataType of the elements in the array.
     * @return the dataType of the elements in the array
     */
    virtual DataType* getDataType() const = 0;

    /**
     * Return true if this is a zero-length array.
     */
    virtual bool isZeroLength() const = 0;
};

} // namespace ghidra
