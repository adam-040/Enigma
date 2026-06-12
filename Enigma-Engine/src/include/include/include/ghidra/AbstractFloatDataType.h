/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AbstractFloatDataType.h
/// \brief Provides a definition of a Float within a program.
#pragma once

#include "BuiltIn.h"

namespace ghidra {

/**
 * Provides a definition of a Float within a program.
 * Translated from: ghidra.program.model.data.AbstractFloatDataType
 */
class AbstractFloatDataType : public BuiltIn {
protected:
    int encodedLength_;
    std::string description_;

    AbstractFloatDataType(const std::string& name, int encodedLength, DataTypeManager* dtm);

    std::string buildIEEE754StandardDescription() const;

    virtual std::string buildDescription() const;

public:
    virtual ~AbstractFloatDataType();

    std::string getMnemonic(Settings* settings) const override;

    std::string getDescription() const override;

    int getLength() const override;

    const std::type_info& getValueClass(Settings* settings) const override;

    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override;

    std::string getDefaultLabelPrefix() const override;

    std::string getCTypeDeclaration(DataOrganization* dataOrganization) const;

    virtual bool hasLanguageDependantLength() const;
};

} // namespace ghidra
