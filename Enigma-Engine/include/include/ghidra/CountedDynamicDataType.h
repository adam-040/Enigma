/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file CountedDynamicDataType.h
/// \brief A dynamic data type that changes the number of elements it contains based on a count.
#pragma once

#include "ghidra/DynamicDataType.h"
#include "ghidra/DataTypeComponent.h"
#include <vector>

namespace ghidra {

/**
 * A dynamic data type that changes the number of elements it contains based on a count
 * found in a header data type. Only valid as a component of another Dynamic data type.
 * Translated from: ghidra.program.model.data.CountedDynamicDataType
 */
class CountedDynamicDataType : public DynamicDataType {
public:
    CountedDynamicDataType(const std::string& name, const std::string& description,
                           DataType* header, DataType* baseStruct,
                           int64_t counterOffset, int counterSize, int64_t mask);
    virtual ~CountedDynamicDataType() = default;

    DataType* getHeader() const { return header_; }
    DataType* getBaseStruct() const { return baseStruct_; }
    int64_t getCounterOffset() const { return counterOffset_; }
    int getCounterSize() const { return counterSize_; }
    int64_t getMask() const { return mask_; }
    std::string getDescription() const override { return description_; }
    int getLength() const override { return -1; }
    int getLength(MemBuffer* buf, int maxLength) override;
    DataType* getReplacementBaseType() override { return this; }
    std::string getCTypeDeclaration(DataOrganization* dataOrganization) override { return getName(); }
    void setDefaultSettings(Settings* settings) override {}

protected:
    std::vector<DataTypeComponent*> getAllComponents(MemBuffer* buf) override;

private:
    int getCount(MemBuffer* buf);

    std::string description_;
    DataType* header_;
    DataType* baseStruct_;
    int64_t counterOffset_;
    int counterSize_;
    int64_t mask_;
};

} // namespace ghidra
