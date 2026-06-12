/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file UnsignedIntegerDataType.h
/// \brief Basic implementation for an unsigned Integer dataType
#pragma once

#include "AbstractUnsignedIntegerDataType.h"

namespace ghidra {

class IntegerDataType;

/**
 * Basic implementation for an unsigned Integer dataType.
 * Translated from: ghidra.program.model.data.UnsignedIntegerDataType
 */
class UnsignedIntegerDataType : public AbstractUnsignedIntegerDataType {
public:
    static UnsignedIntegerDataType& dataType();

    explicit UnsignedIntegerDataType(DataTypeManager* dtm = nullptr);

    bool hasLanguageDependantLength() const override;

    int getLength() const override;

    std::string getDescription() const override;

    std::string getCDeclaration() const;

    AbstractIntegerDataType* getOppositeSignednessDataType() const override;

    DataType* clone(DataTypeManager* dtm) const override;

    std::string getCTypeDeclaration(DataOrganization* dataOrganization) const;
};

} // namespace ghidra
