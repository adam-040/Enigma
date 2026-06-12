/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file BooleanDataType.h
/// \brief Provides a definition of an Ascii byte in a program.
#pragma once

#include "BuiltIn.h"

namespace ghidra {

class BooleanDataType : public BuiltIn {
public:
    static BooleanDataType& dataType();

    BooleanDataType(DataTypeManager* dtm = nullptr);

    std::string getMnemonic(Settings* settings) const override;

    std::string getDecompilerDisplayName() const override;

    int getLength() const override;

    int getAlignedLength() const override;

    std::string getDescription() const override;

    const std::type_info& getValueClass(Settings* settings) const override;

    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override;

    DataType* clone(DataTypeManager* dtm) const override;

    std::string getDefaultLabelPrefix() const override;
};

} // namespace ghidra
