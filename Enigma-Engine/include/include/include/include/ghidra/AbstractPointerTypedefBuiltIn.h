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
#include <ghidra/TypeDef.h>
#include <ghidra/TypedefDataType.h>
#include <ghidra/PointerDataType.h>
#include <string>

namespace ghidra {

class Pointer;

class AbstractPointerTypedefBuiltIn : public BuiltIn, public virtual TypeDef {
    std::string typedefName_;
    TypedefDataType* modelTypedef_ = nullptr;
public:
    AbstractPointerTypedefBuiltIn(const std::string& name, DataType* referencedDataType,
                                  int pointerSize, DataTypeManager* dtm);
    AbstractPointerTypedefBuiltIn(const std::string& name, Pointer* pointerDataType,
                                  DataTypeManager* dtm);
    ~AbstractPointerTypedefBuiltIn() override;

    void enableAutoNaming() override;
    bool isAutoNamed() const override;

    DataType* getReferencedDataType();
    bool isEquivalent(const DataType* obj) const override;
    std::string getName() const override;
    bool hasLanguageDependantLength() const override;
    int getLength() const override;
    int getAlignedLength() const override;
    DataType* getDataType() const override;
    DataType* getBaseDataType() const override;
    bool dependsOn(const DataType* dt) const override;
    std::string toString() const;
    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override;
    DataType* clone(DataTypeManager* dtm) const override;

    std::string getDescription() const override;
    std::vector<SettingsDefinition*> getSettingsDefinitions() const override;

protected:
    bool hasGeneratedNamed() const { return typedefName_.empty(); }
    void setTypedefName(const std::string& name);
};

} // namespace ghidra
