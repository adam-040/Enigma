/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file RepeatedDynamicDataType.h
/// \brief Dynamic data type with header + terminator-separated repeated entries.
#pragma once

#include "ghidra/DynamicDataType.h"
#include "ghidra/DataTypeComponent.h"
#include <vector>

namespace ghidra {

/**
 * Template for a repeated Dynamic Data Type. After each data type, including the header,
 * there is a terminator value that specifies whether more data structures follow.
 * TerminatorSize can be 1, 2, 4, or 8 bytes.
 * Translated from: ghidra.program.model.data.RepeatedDynamicDataType
 */
class RepeatedDynamicDataType : public DynamicDataType {
public:
    RepeatedDynamicDataType(const std::string& name, const std::string& description,
                            DataType* header, DataType* baseStruct,
                            int64_t terminatorValue, int terminatorSize,
                            DataTypeManager* dtm);
    virtual ~RepeatedDynamicDataType() = default;

    std::string getDescription() const override { return description_; }
    int getLength() const override { return -1; }
    int getLength(MemBuffer* buf, int maxLength) override;
    DataType* getReplacementBaseType() override { return this; }
    std::string getCTypeDeclaration(DataOrganization* dataOrganization) override { return getName(); }
    void setDefaultSettings(Settings* settings) override {}
    DataType* getHeader() const { return header_; }
    DataType* getBaseStruct() const { return baseStruct_; }
    int64_t getTerminatorValue() const { return terminatorValue_; }
    int getTerminatorSize() const { return terminatorSize_; }

protected:
    std::vector<DataTypeComponent*> getAllComponents(MemBuffer* buf) override;
    virtual bool moreComponents(MemBuffer* buf) = 0;

    std::string description_;
    DataType* header_;
    DataType* baseStruct_;
    int64_t terminatorValue_;
    int terminatorSize_;
};

} // namespace ghidra
