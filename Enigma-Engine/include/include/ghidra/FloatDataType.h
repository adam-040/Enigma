/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file FloatDataType.h
/// \brief Provides a definition of a Float within a program.
#pragma once

#include "AbstractFloatDataType.h"

namespace ghidra {

class FloatDataType : public AbstractFloatDataType {
private:
    static int getFloatSize(DataTypeManager* dtm);

public:
    static FloatDataType& dataType();

    explicit FloatDataType(DataTypeManager* dtm = nullptr);

    std::string buildDescription() const override;

    DataType* clone(DataTypeManager* dtm) const override;

    bool hasLanguageDependantLength() const override;
};

} // namespace ghidra
