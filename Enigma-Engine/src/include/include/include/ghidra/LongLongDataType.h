/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file LongLongDataType.h
/// \brief Basic implementation for a Signed Long Long Integer dataType
#pragma once

#include "AbstractSignedIntegerDataType.h"

namespace ghidra {

class UnsignedLongLongDataType;

/**
 * Basic implementation for a Signed Long Long Integer dataType.
 * Translated from: ghidra.program.model.data.LongLongDataType
 */
class LongLongDataType : public AbstractSignedIntegerDataType {
public:
    static LongLongDataType& dataType();

    explicit LongLongDataType(DataTypeManager* dtm = nullptr);

    bool hasLanguageDependantLength() const override;

    int getLength() const override;

    std::string getDescription() const override;

    std::string getCDeclaration() const;

    AbstractIntegerDataType* getOppositeSignednessDataType() const override;

    DataType* clone(DataTypeManager* dtm) const override;

    std::string getCTypeDeclaration(DataOrganization* dataOrganization) const;
};

} // namespace ghidra
