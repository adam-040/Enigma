/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ShiftedAddressDataType.h
/// \brief Shifted address data type (compiler-spec shifted pointer)
#pragma once

#include "ghidra/BuiltIn.h"
#include "ghidra/Address.h"
#include <cstdint>

namespace ghidra {

class AddressSpace;

class ShiftedAddressDataType : public BuiltIn {
public:
    static ShiftedAddressDataType& dataType();

    explicit ShiftedAddressDataType(DataTypeManager* dtm = nullptr);

    std::string getDescription() const override;

    int getLength() const override;

    bool hasLanguageDependantLength() const override;

    std::string getMnemonic(Settings* settings) const override;

    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override;

    const std::type_info& getValueClass(Settings* settings) const override;

    DataType* clone(DataTypeManager* dtm) const override;

    static Address getAddressValue(MemBuffer* buf, int size, int shift, AddressSpace* targetSpace);

protected:
    std::string getString(MemBuffer* buf, Settings* settings) const;
};

} // namespace ghidra
