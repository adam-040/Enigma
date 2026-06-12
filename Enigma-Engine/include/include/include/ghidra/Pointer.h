/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Pointer.h
/// \brief Interface for pointers
#pragma once

#include "DataType.h"

namespace ghidra {

/**
 * Interface for pointers
 * Translated from: ghidra.program.model.data.Pointer
 */
class Pointer : public virtual DataType {
public:
    static inline const std::string NaP = "NaP";

    virtual ~Pointer() = default;

    /**
     * Returns the "pointed to" dataType
     * @return referenced datatype (may be null)
     */
    virtual DataType* getDataType() const = 0;

    /**
     * Creates a pointer to the indicated data type.
     * @param dataType the data type to point to.
     * @return the newly created pointer.
     */
    virtual Pointer* newPointer(DataType* dataType) const = 0;
};

} // namespace ghidra
