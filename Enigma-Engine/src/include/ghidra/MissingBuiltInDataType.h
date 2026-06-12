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

#include <ghidra/DataTypeImpl.h>
#include <ghidra/Dynamic.h>
#include <string>

namespace ghidra {

class MissingBuiltInDataType : public DataTypeImpl, public Dynamic {
    std::string missingBuiltInName_;
    std::string missingBuiltInClassPath_;
public:
    MissingBuiltInDataType(const CategoryPath& path, const std::string& missingBuiltInName,
                           const std::string& missingBuiltInClassPath, DataTypeManager* dtm);

    std::string getMissingBuiltInName() const { return missingBuiltInName_; }
    std::string getMissingBuiltInClassPath() const { return missingBuiltInClassPath_; }

    std::string getMnemonic(Settings* settings) const override;
    int getLength() const override;
    bool canSpecifyLength() override;
    int getLength(MemBuffer* buf, int maxLength) override;
    std::string getDescription() const override;
    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override;
    DataType* clone(DataTypeManager* dtm) const override;
    DataType* copy(DataTypeManager* dtm) const override;
    bool isEquivalent(const DataType* dt) const override;
    int64_t getLastChangeTime() const override;
    DataType* getReplacementBaseType() override;
    void setDefaultSettings(Settings* settings) override;
    std::string getCTypeDeclaration(DataOrganization* dataOrganization) override;
};

} // namespace ghidra
