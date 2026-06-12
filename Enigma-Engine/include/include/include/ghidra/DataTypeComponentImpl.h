/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataTypeComponentImpl.h
/// \brief Concrete implementation of DataTypeComponent.
#pragma once

#include "DataTypeComponent.h"
#include "BitFieldDataType.h"

namespace ghidra {

/**
 * Concrete implementation of DataTypeComponent.
 * Translated from: ghidra.program.model.data.DataTypeComponentImpl
 */
class DataTypeComponentImpl : public DataTypeComponent {
protected:
    DataType* dataType_;
    DataType* parent_;
    bool ownsDataType_;
    int length_;
    int ordinal_;
    int offset_;
    std::string fieldName_;
    std::string comment_;

public:
    DataTypeComponentImpl(DataType* dataType, int length, int ordinal, int offset,
                          const std::string& fieldName = "", const std::string& comment = "",
                          DataType* parent = nullptr, bool ownsDataType = false);

    ~DataTypeComponentImpl() override;

    DataType* getDataType() const override { return dataType_; }
    DataType* getParent() const override { return parent_; }
    bool isBitFieldComponent() const override;
    bool isZeroBitFieldComponent() const override;
    int getOrdinal() const override { return ordinal_; }
    int getOffset() const override { return offset_; }
    int getEndOffset() const override { return offset_ + length_ - 1; }
    int getLength() const override { return length_; }
    std::string getComment() const override { return comment_; }
    Settings* getDefaultSettings() const override { return nullptr; }

    DataTypeComponent* setComment(const std::string& comment) override;

    std::string getFieldName() const override { return fieldName_; }

    DataTypeComponent* setFieldName(const std::string& fieldName) override;

    void setOffset(int offset) { offset_ = offset; }
    void setOrdinal(int ordinal) { ordinal_ = ordinal; }
    void setLength(int length) { length_ = length; }
    void setOwnsDataType(bool ownsDataType) { ownsDataType_ = ownsDataType; }
    bool ownsDataType() const { return ownsDataType_; }
    void replaceDataType(DataType* dataType, bool ownsDataType);

    bool isEquivalent(const DataTypeComponent* dtc) const override;

    bool isUndefined() const override {
        return false;
    }
};

} // namespace ghidra
