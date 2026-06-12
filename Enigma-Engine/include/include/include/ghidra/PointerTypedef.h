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

#include <ghidra/GenericDataType.h>
#include <ghidra/TypeDef.h>
#include <ghidra/TypedefDataType.h>
#include <ghidra/PointerDataType.h>
#include <ghidra/PointerTypeSettingsDefinition.h>
#include <ghidra/AddressSpaceSettingsDefinition.h>
#include <ghidra/ComponentOffsetSettingsDefinition.h>
#include <ghidra/OffsetShiftSettingsDefinition.h>
#include <ghidra/OffsetMaskSettingsDefinition.h>
#include <string>

namespace ghidra {

class AddressSpace;

class PointerTypedef : public GenericDataType, public virtual TypeDef {
    bool isAutoNamed_ = false;
    TypedefDataType* modelTypedef_ = nullptr;
public:
    PointerTypedef(const std::string& typeDefName, DataType* referencedDataType,
                   int pointerSize, DataTypeManager* dtm, AddressSpace* space);
    PointerTypedef(const std::string& typeDefName, DataType* referencedDataType,
                   int pointerSize, DataTypeManager* dtm, PointerType type);
    PointerTypedef(const std::string& typeDefName, DataType* referencedDataType,
                   int pointerSize, DataTypeManager* dtm, long componentOffset);
    PointerTypedef(const std::string& typeDefName, DataType* referencedDataType,
                   int pointerSize, DataTypeManager* dtm);
    PointerTypedef(const std::string& typeDefName, Pointer* pointerDataType,
                   DataTypeManager* dtm);
    ~PointerTypedef() override;

    void enableAutoNaming() override;
    bool isAutoNamed() const override;

    DataType* getReferencedDataType();

    bool isEquivalent(const DataType* obj) const override;
    std::string getDescription() const override;
    std::string getName() const override;
    void setName(const std::string& name) override;
    bool hasLanguageDependantLength() const override;
    int getLength() const override;
    int getAlignedLength() const override;
    DataType* getDataType() const override;
    DataType* getBaseDataType() const override;
    std::vector<SettingsDefinition*> getSettingsDefinitions() const override;
    std::vector<TypeDefSettingsDefinition*> getTypeDefSettingsDefinitions() const override;
    Settings* getDefaultSettings() const override;
    bool dependsOn(const DataType* dt) const override;
    std::string toString() const;
    const std::type_info& getValueClass(Settings* settings) const override;
    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override;
    PointerTypedef* clone(DataTypeManager* dtm) const override;
    PointerTypedef* copy(DataTypeManager* dtm) const;

private:
    static int getPreferredPointerSize(int pointerSize, DataTypeManager* dtm, AddressSpace* space);
    void init(const std::string& typeDefName, DataType* baseType);
};

} // namespace ghidra
