/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file TerminatedUnicodeDataType.h
/// \brief String (Null Terminated UTF-16 Unicode)
#pragma once

#include "AbstractStringDataType.h"

namespace ghidra {

class TerminatedUnicodeDataType : public AbstractStringDataType {
public:
    static TerminatedUnicodeDataType& dataType();

    explicit TerminatedUnicodeDataType(DataTypeManager* dtm = nullptr);

    DataType* clone(DataTypeManager* dtm) const override;
};

} // namespace ghidra
