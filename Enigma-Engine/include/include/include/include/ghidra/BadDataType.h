/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once

#include <ghidra/BuiltIn.h>
#include <ghidra/Dynamic.h>

namespace ghidra {

class BadDataType : public BuiltIn, public Dynamic {
public:
    static BadDataType dataType;

    BadDataType();

    DataType* clone(DataTypeManager* dtm) const override;
    std::string getMnemonic(Settings* settings) const override;
    int getLength() const override;
    std::string getDescription() const override;
    bool isEquivalent(const DataType* dt) const override;
    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override;
    bool canSpecifyLength() override;
    int getLength(MemBuffer* buf, int maxLength) override;
    DataType* getReplacementBaseType() override;
    std::string getCTypeDeclaration(DataOrganization* dataOrganization) override;
    void setDefaultSettings(Settings* settings) override;
};

} // namespace ghidra
