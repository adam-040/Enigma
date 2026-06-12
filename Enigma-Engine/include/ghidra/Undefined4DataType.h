/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Undefined4DataType.h
/// \brief Undefined 4-byte data type.
#pragma once

#include "ghidra/Undefined.h"

namespace ghidra {

class Undefined4DataType : public Undefined {
public:
    Undefined4DataType(DataTypeManager* dtm = nullptr);

    std::string getDescription() const override;
    std::string getMnemonic(Settings* settings) const override;
    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override;
    DataType* clone(DataTypeManager* dtm) const override;
};

} // namespace ghidra
