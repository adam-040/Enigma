/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file RepeatedStringDataType.h
/// \brief Some number of repeated strings; each string can be of variable length.
#pragma once

#include "ghidra/RepeatCountDataType.h"

namespace ghidra {

/**
 * Repeated string data type. Structure:
 *   numberOfStrings = N (2-byte count)
 *   String1 ... StringN
 * Translated from: ghidra.program.model.data.RepeatedStringDataType
 */
class RepeatedStringDataType : public RepeatCountDataType {
public:
    RepeatedStringDataType();
    explicit RepeatedStringDataType(DataTypeManager* dtm);

    std::string getDescription() const override;
    DataType* clone(DataTypeManager* dtm) const override;
};

} // namespace ghidra
