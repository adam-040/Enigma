/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file FileTimeDataType.h
/// \brief FileTime timestamp data type (100ns ticks since Jan 1, 1601)
#pragma once

#include "ghidra/BuiltIn.h"

namespace ghidra {

class FileTimeDataType : public BuiltIn {
public:
    explicit FileTimeDataType(DataTypeManager* dtm = nullptr);

    std::string getDescription() const override;

    int getLength() const override;

    std::string getMnemonic(Settings* settings) const override;

    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override;

    const std::type_info& getValueClass(Settings* settings) const override;

    DataType* clone(DataTypeManager* dtm) const override;
};

} // namespace ghidra
