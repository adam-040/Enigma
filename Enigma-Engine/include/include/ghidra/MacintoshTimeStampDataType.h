/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file MacintoshTimeStampDataType.h
/// \brief Mac OS timestamp data type (seconds since Jan 1, 1904)
#pragma once

#include "ghidra/BuiltIn.h"

namespace ghidra {

class MacintoshTimeStampDataType : public BuiltIn {
public:
    explicit MacintoshTimeStampDataType(DataTypeManager* dtm = nullptr);

    std::string getDescription() const override;

    int getLength() const override;

    std::string getMnemonic(Settings* settings) const override;

    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override;

    const std::type_info& getValueClass(Settings* settings) const override;

    DataType* clone(DataTypeManager* dtm) const override;
};

} // namespace ghidra
