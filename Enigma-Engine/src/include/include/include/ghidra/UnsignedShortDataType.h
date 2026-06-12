/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file UnsignedShortDataType.h
/// \brief Basic implementation for an unsigned Short Integer dataType
#pragma once

#include "AbstractUnsignedIntegerDataType.h"

namespace ghidra {

class ShortDataType;

/**
 * Basic implementation for an unsigned Short Integer dataType.
 * Translated from: ghidra.program.model.data.UnsignedShortDataType
 */
class UnsignedShortDataType : public AbstractUnsignedIntegerDataType {
public:
    static UnsignedShortDataType& dataType();

    explicit UnsignedShortDataType(DataTypeManager* dtm = nullptr);

    bool hasLanguageDependantLength() const override;

    int getLength() const override;

    std::string getDescription() const override;

    std::string getCDeclaration() const;

    AbstractIntegerDataType* getOppositeSignednessDataType() const override;

    DataType* clone(DataTypeManager* dtm) const override;

    std::string getCTypeDeclaration(DataOrganization* dataOrganization) const;
};

} // namespace ghidra
