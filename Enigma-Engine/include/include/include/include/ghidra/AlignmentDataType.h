/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AlignmentDataType.h
/// \brief Consumes alignment/repeating bytes.
#pragma once

#include "BuiltIn.h"
#include "Dynamic.h"

namespace ghidra {

class AlignmentDataType : public BuiltIn, public Dynamic {
    static constexpr int MAX_LENGTH = 1024;

    int computeLength(MemBuffer* buf) const;

public:
    static AlignmentDataType& dataType();

    explicit AlignmentDataType(DataTypeManager* dtm = nullptr);

    DataType* clone(DataTypeManager* dtm) const override;

    std::string getDescription() const override;

    std::string getMnemonic(Settings* settings) const override;

    bool canSpecifyLength() override;

    int getLength(MemBuffer* buf, int maxLength) override;

    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override;

    const std::type_info& getValueClass(Settings* settings) const override;

    int getLength() const override;

    DataType* getReplacementBaseType() override;

    std::string getCTypeDeclaration(DataOrganization* dataOrganization) override;
    void setDefaultSettings(Settings* settings) override;
};

} // namespace ghidra
