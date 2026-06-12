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
#include <ghidra/FormatSettingsDefinition.h>
#include <string>

namespace ghidra {

class AbstractLeb128DataType : public BuiltIn, public Dynamic {
public:
    AbstractLeb128DataType(const std::string& name, bool isSigned, DataTypeManager* dtm);

    std::string getMnemonic(Settings* settings) const override;
    const std::type_info& getValueClass(Settings* settings) const override;
    std::string getDescription() const override;
    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override;
    int getLength() const override;
    int getLength(MemBuffer* buf, int maxLength) override;
    bool canSpecifyLength() override;
    DataType* getReplacementBaseType() override;
    std::string getDefaultLabelPrefix() const override;

    std::string getCTypeDeclaration(DataOrganization* dataOrganization) override;
    void setDefaultSettings(Settings* settings) override;

protected:
    bool isSigned_;
};

} // namespace ghidra
