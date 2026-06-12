/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DefaultDataType.h
/// \brief Implementation of an undefined byte
#pragma once

#include "AbstractDataType.h"
#include "Scalar.h"

namespace ghidra {

class DefaultDataType : public AbstractDataType {
public:
    static DefaultDataType& dataType();

    DefaultDataType();

    std::string getMnemonic(Settings* settings) const override;

    int getLength() const override;

    int getAlignedLength() const override;

    std::string getDescription() const override;

    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override;

    const std::type_info& getValueClass(Settings* settings) const override;

    DataType* clone(DataTypeManager* dtm) const override;

    DataType* copy(DataTypeManager* dtm) const override;

    bool isEquivalent(const DataType* dt) const override;

    int getAlignment() const override;

    std::vector<SettingsDefinition*> getSettingsDefinitions() const override;

    Settings* getDefaultSettings() const override;

    void addParent(DataType* dt) override;

    void removeParent(DataType* dt) override;

    int64_t getLastChangeTime() const override;
};

} // namespace ghidra
