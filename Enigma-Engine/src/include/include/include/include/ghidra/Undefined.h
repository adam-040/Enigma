/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Undefined.h
/// \brief Identifies an undefined data type.
#pragma once

#include "BuiltIn.h"

namespace ghidra {

/**
 * Base class for the family of Undefined data types (sizes 1..8).
 * Translated from: ghidra.program.model.data.Undefined
 */
class Undefined : public BuiltIn {
protected:
    int size_;

    Undefined(const std::string& name, DataTypeManager* dtm, int size);

public:
    virtual ~Undefined();

    int getLength() const override;
    std::string getDescription() const override;
    DataType* clone(DataTypeManager* dtm) const override;
    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override;

    static DataType* getUndefinedDataType(int size);
    static bool isUndefined(const DataType* dataType);
    static bool isUndefinedArray(const DataType* dataType);
};

} // namespace ghidra
