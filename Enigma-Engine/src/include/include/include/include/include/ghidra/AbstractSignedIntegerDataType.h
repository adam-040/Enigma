/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AbstractSignedIntegerDataType.h
/// \brief Base type for signed integer data types.
#pragma once

#include "AbstractIntegerDataType.h"

namespace ghidra {

class AbstractSignedIntegerDataType : public AbstractIntegerDataType {
protected:
    AbstractSignedIntegerDataType(const std::string& name, DataTypeManager* dtm);

public:
    virtual ~AbstractSignedIntegerDataType();

    bool isSigned() const override;
};

} // namespace ghidra
