/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SignedQWordDataType.h
/// \brief Signed Quad-Word (sdq, 8-bytes)
#pragma once

#include "AbstractSignedIntegerDataType.h"

namespace ghidra {

class QWordDataType;

class SignedQWordDataType : public AbstractSignedIntegerDataType {
public:
    static SignedQWordDataType& dataType();

    explicit SignedQWordDataType(DataTypeManager* dtm = nullptr);

    std::string getDescription() const override;
    int getLength() const override;
    std::string getAssemblyMnemonic() const override;
    AbstractIntegerDataType* getOppositeSignednessDataType() const override;
    DataType* clone(DataTypeManager* dtm) const override;
};

} // namespace ghidra
