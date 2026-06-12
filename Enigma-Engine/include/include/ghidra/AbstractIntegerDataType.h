/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AbstractIntegerDataType.h
/// \brief Base type for integer data types.
#pragma once

#include "BuiltIn.h"

namespace ghidra {

class AbstractIntegerDataType : public BuiltIn {
public:
    static const std::string C_SIGNED_CHAR;
    static const std::string C_UNSIGNED_CHAR;
    static const std::string C_SIGNED_SHORT;
    static const std::string C_UNSIGNED_SHORT;
    static const std::string C_SIGNED_INT;
    static const std::string C_UNSIGNED_INT;
    static const std::string C_SIGNED_LONG;
    static const std::string C_UNSIGNED_LONG;
    static const std::string C_SIGNED_LONGLONG;
    static const std::string C_UNSIGNED_LONGLONG;

protected:
    AbstractIntegerDataType(const std::string& name, DataTypeManager* dtm);

public:
    virtual ~AbstractIntegerDataType();

    virtual bool isSigned() const = 0;

    std::string getDefaultLabelPrefix() const override;

    std::string getMnemonic(Settings* settings) const override;

    virtual std::string getAssemblyMnemonic() const;

    virtual std::string getCMnemonic() const;

    std::string getCDeclaration() const;

    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override;

    const std::type_info& getValueClass(Settings* settings) const override;

    virtual AbstractIntegerDataType* getOppositeSignednessDataType() const = 0;

    bool isEquivalent(const DataType* dt) const override;
};

} // namespace ghidra
