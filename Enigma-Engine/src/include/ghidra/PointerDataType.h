/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PointerDataType.h
/// \brief Basic implementation for a pointer dataType
#pragma once

#include "BuiltIn.h"
#include "Pointer.h"

namespace ghidra {

class PointerDataType : public BuiltIn, public virtual Pointer {
protected:
    DataType* referencedDataType_;
    int length_;
    bool ownsReferencedDataType_;
    bool deleted_;
    mutable std::string displayName_;

    static std::string constructUniqueName(DataType* referencedDataType, int ptrLength);

public:
    static PointerDataType& dataType();

    PointerDataType(DataTypeManager* dtm = nullptr);

    PointerDataType(DataType* referencedDataType, DataTypeManager* dtm = nullptr);

    PointerDataType(DataType* referencedDataType, int length, DataTypeManager* dtm = nullptr,
                    bool ownsReferencedDataType = false);

    ~PointerDataType() override;

    DataType* clone(DataTypeManager* dtm) const override;

    DataType* getDataType() const override;

    Pointer* newPointer(DataType* dataType) const override;

    bool hasLanguageDependantLength() const override;

    int getLength() const override;

    std::string getDefaultLabelPrefix() const override;

    std::string getDisplayName() const override;

    std::string getDescription() const override;

    std::string getMnemonic(Settings* settings) const override;

    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override;

    const std::type_info& getValueClass(Settings* settings) const override;

    bool isEquivalent(const DataType* dt) const override;
};

} // namespace ghidra
