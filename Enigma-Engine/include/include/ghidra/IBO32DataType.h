/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file IBO32DataType.h
/// \brief 32-bit Image Base Offset relative pointer-typedef BuiltIn
#pragma once

#include "ghidra/AbstractPointerTypedefBuiltIn.h"

namespace ghidra {

class IBO32DataType : public AbstractPointerTypedefBuiltIn {
public:
    static IBO32DataType& dataType();

    explicit IBO32DataType(DataTypeManager* dtm = nullptr);

    std::string getDescription() const override;

    std::string getMnemonic(Settings* settings) const override;

    DataType* clone(DataTypeManager* dtm) const override;
};

} // namespace ghidra
