/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file RepeatCountDataType.h
/// \brief Dynamic data type with a leading 2-byte count followed by N repeats of a DataType.
#pragma once

#include "ghidra/DynamicDataType.h"
#include "ghidra/DataTypeComponent.h"
#include <vector>

namespace ghidra {

/**
 * Base abstract data type for a dynamic structure that contains some number of
 * repeated data types. The first 2 bytes are a little-endian count of the
 * following repeated DataType instances.
 * Translated from: ghidra.program.model.data.RepeatCountDataType
 */
class RepeatCountDataType : public DynamicDataType {
public:
    RepeatCountDataType(DataType* repeatDataType, const CategoryPath& path,
                        const std::string& name, DataTypeManager* dtm);
    virtual ~RepeatCountDataType() = default;

    DataType* getRepeatDataType() const { return repeatDataType_; }

    std::string getMnemonic(Settings* settings) const override;
    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override;
    void* getValue(MemBuffer* buf, Settings* settings, int length) const;
    int getLength() const override { return -1; }
    int getLength(MemBuffer* buf, int maxLength) override;
    DataType* getReplacementBaseType() override { return this; }
    std::string getCTypeDeclaration(DataOrganization* dataOrganization) override { return getName(); }
    void setDefaultSettings(Settings* settings) override {}

protected:
    std::vector<DataTypeComponent*> getAllComponents(MemBuffer* buf) override;

private:
    DataType* repeatDataType_;
};

} // namespace ghidra
