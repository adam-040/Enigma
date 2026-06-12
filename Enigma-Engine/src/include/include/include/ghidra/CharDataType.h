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

#include "AbstractIntegerDataType.h"

namespace ghidra {

class CharDataType : public AbstractIntegerDataType {
public:
    static CharDataType& dataType();

    explicit CharDataType(DataTypeManager* dtm = nullptr);

    bool isSigned() const override;
    std::string getDescription() const override;
    int getLength() const override;
    AbstractIntegerDataType* getOppositeSignednessDataType() const override;
    DataType* clone(DataTypeManager* dtm) const override;
};

} // namespace ghidra
