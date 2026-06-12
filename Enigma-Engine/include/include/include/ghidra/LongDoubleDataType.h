/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file LongDoubleDataType.h
/// \brief Provides a definition of a Long Double within a program.
#pragma once

#include "AbstractFloatDataType.h"

namespace ghidra {

class LongDoubleDataType : public AbstractFloatDataType {
private:
    static int getLongDoubleSize(DataTypeManager* dtm);

public:
    static LongDoubleDataType& dataType();

    explicit LongDoubleDataType(DataTypeManager* dtm = nullptr);

    std::string buildDescription() const override;

    DataType* clone(DataTypeManager* dtm) const override;

    std::string getCTypeDeclaration(DataOrganization* dataOrganization) const;

    bool hasLanguageDependantLength() const override;
};

} // namespace ghidra
