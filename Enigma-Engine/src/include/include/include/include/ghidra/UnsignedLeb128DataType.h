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

#include <ghidra/AbstractLeb128DataType.h>

namespace ghidra {

class UnsignedLeb128DataType : public AbstractLeb128DataType {
public:
    static UnsignedLeb128DataType& dataType();

    explicit UnsignedLeb128DataType(DataTypeManager* dtm = nullptr);

    DataType* clone(DataTypeManager* dtm) const override;

    std::string getDescription() const override;
};

} // namespace ghidra
