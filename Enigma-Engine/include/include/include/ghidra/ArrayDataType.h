/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ArrayDataType.h
/// \brief Basic implementation of the Array interface.
#pragma once

#include "DataTypeImpl.h"
#include "Array.h"

namespace ghidra {

class ArrayDataType : public DataTypeImpl, public virtual Array {
protected:
    int numElements_;
    DataType* dataType_;
    int elementLength_;
    bool ownsDataType_;
    bool deleted_;

public:
    ArrayDataType(DataType* dataType, int numElements, int elementLength = -1, DataTypeManager* dtm = nullptr,
                  bool ownsDataType = false);

    ~ArrayDataType() override;

    bool hasLanguageDependantLength() const override;

    bool isEquivalent(const DataType* obj) const override;

    int getNumElements() const override;

    std::string getMnemonic(Settings* settings) const override;

    bool isZeroLength() const override;

    int getLength() const override;

    int getAlignedLength() const override;

    std::string getDescription() const override;

    DataType* getDataType() const override;

    DataType* clone(DataTypeManager* dtm) const override;

    DataType* copy(DataTypeManager* dtm) const override;

    const std::type_info& getValueClass(Settings* settings) const override;

    int getElementLength() const override;

    bool isDeleted() const override;

    CategoryPath getCategoryPath() const override;

    bool dependsOn(const DataType* dt) const override;

    std::string getDefaultLabelPrefix() const override;

    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override;
};

} // namespace ghidra
