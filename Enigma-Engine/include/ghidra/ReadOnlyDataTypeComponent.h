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

#include <ghidra/DataTypeComponent.h>
#include <ghidra/DataType.h>
#include <ghidra/SettingsImpl.h>
#include <string>

namespace ghidra {

class ReadOnlyDataTypeComponent : public DataTypeComponent {
public:
    ReadOnlyDataTypeComponent(DataType* dataType, DataType* parent,
                              int length, int ordinal, int offset,
                              const std::string& fieldName = "",
                              const std::string& comment = "");

    DataType* getDataType() const override;
    DataType* getParent() const override;

    bool isBitFieldComponent() const override;
    bool isZeroBitFieldComponent() const override;

    int getOrdinal() const override;
    int getOffset() const override;
    int getEndOffset() const override;
    int getLength() const override;

    std::string getComment() const override;
    DataTypeComponent* setComment(const std::string& comment) override;

    std::string getFieldName() const override;
    DataTypeComponent* setFieldName(const std::string& fieldName) override;

    Settings* getDefaultSettings() const override;
    bool isEquivalent(const DataTypeComponent* dtc) const override;
    bool isUndefined() const override;

private:
    DataType* dataType_;
    DataType* parent_;
    int offset_;
    int ordinal_;
    std::string comment_;
    int length_;
    std::string fieldName_;
    mutable SettingsImpl* defaultSettings_;

    static bool isSameString(const std::string& s1, const std::string& s2);
};

} // namespace ghidra
