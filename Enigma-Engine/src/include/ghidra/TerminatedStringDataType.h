/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once

#include <ghidra/AbstractStringDataType.h>

namespace ghidra {

class TerminatedStringDataType : public AbstractStringDataType {
public:
    static TerminatedStringDataType& dataType();

    explicit TerminatedStringDataType(DataTypeManager* dtm = nullptr);

    DataType* clone(DataTypeManager* dtm) const override;
};

} // namespace ghidra
