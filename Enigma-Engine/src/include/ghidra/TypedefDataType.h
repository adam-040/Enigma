/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file TypedefDataType.h
/// \brief Basic implementation for the typedef dataType.
#pragma once

#include "GenericDataType.h"
#include "TypeDef.h"

namespace ghidra {

class TypedefDataType : public GenericDataType, public virtual TypeDef {
protected:
    DataType* dataType_;
    bool ownsDataType_;
    bool isAutoNamed_;
    bool deleted_;

public:
    TypedefDataType(const std::string& name, DataType* dt);

    TypedefDataType(const CategoryPath& path, const std::string& name, DataType* dt, DataTypeManager* dtm = nullptr);

    /// Constructor with explicit base ownership.  Used by builtin typedef
    /// models (PointerTypedef, AbstractPointerTypedefBuiltIn) that hand a
    /// freshly created internal base to the typedef.
    TypedefDataType(const CategoryPath& path, const std::string& name, DataType* dt,
                    DataTypeManager* dtm, bool ownsDataType);

    ~TypedefDataType() override;

    void enableAutoNaming() override;

    bool isAutoNamed() const override;

    std::string getDefaultLabelPrefix() const override;

    bool hasLanguageDependantLength() const override;

    bool isEquivalent(const DataType* obj) const override;

    std::string getMnemonic(Settings* settings) const override;

    DataType* getDataType() const override;

    std::string getDescription() const override;

    bool isZeroLength() const override;

    int getLength() const override;

    int getAlignedLength() const override;

    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override;

    const std::type_info& getValueClass(Settings* settings) const override;

    DataType* clone(DataTypeManager* dtm) const override;

    DataType* copy(DataTypeManager* dtm) const override;

    std::string getName() const override;

    CategoryPath getCategoryPath() const override;

    DataType* getBaseDataType() const override;

    bool isDeleted() const override;

    bool dependsOn(const DataType* dt) const override;
};

} // namespace ghidra
