/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file EnumDataType.h
/// \brief Basic implementation for Enum data types.
#pragma once

#include "GenericDataType.h"
#include "Enum.h"
#include <map>
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace ghidra {

class EnumDataType : public GenericDataType, public virtual Enum {
protected:
    std::map<std::string, long long> nameMap_;
    std::map<std::string, std::string> commentMap_;
    std::map<long long, std::vector<std::string>> valueMap_;
    int length_;
    EnumSignedState signedState_;

    void checkValue(long long value) const;

    EnumSignedState computeSignedness() const;

    long long getMaxPossibleValue(int bytes, bool allowNegativeValues) const;

    long long getMinPossibleValue(int bytes, bool allowNegativeValues) const;

public:
    EnumDataType(const std::string& name, int length);

    EnumDataType(const CategoryPath& path, const std::string& name, int length, DataTypeManager* dtm = nullptr);

    using GenericDataType::getName;

    long long getValue(const std::string& name) const override;

    std::string getName(long long value) const override;

    std::vector<std::string> getNames(long long value) const override;

    std::string getComment(const std::string& name) const override;

    std::vector<long long> getValues() const override;

    std::vector<std::string> getNames() const override;

    int getCount() const override;

    void add(const std::string& name, long long value) override;

    void add(const std::string& name, long long value, const std::string& comment) override;

    void remove(const std::string& name) override;

    DataType* copy(DataTypeManager* dtm) const override;

    DataType* clone(DataTypeManager* dtm) const override;

    std::string getMnemonic(Settings* /*settings*/) const override;

    int getLength() const override;

    int getAlignedLength() const override;

    bool isSigned() const override;

    EnumSignedState getSignedState() const override;

    long long getMinPossibleValue() const override;

    long long getMaxPossibleValue() const override;

    int getMinimumPossibleLength() const override;

    bool contains(const std::string& name) const override;

    bool contains(long long value) const override;

    bool isEquivalent(const DataType* dt) const override;

    const std::type_info& getValueClass(Settings* /*settings*/) const override;

    std::string getRepresentation(MemBuffer* /*buf*/, Settings* /*settings*/, int /*length*/) const override;
};

} // namespace ghidra
