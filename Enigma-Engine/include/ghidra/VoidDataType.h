/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file VoidDataType.h
/// \brief Special dataType used only for function return types.
#pragma once

#include "AbstractDataType.h"

namespace ghidra {

class VoidDataType : public AbstractDataType {
public:
    static VoidDataType& dataType();

    explicit VoidDataType(DataTypeManager* dtm = nullptr);

    std::string getMnemonic(Settings* settings) const override;

    int getLength() const override;

    int getAlignedLength() const override;

    bool isZeroLength() const override;

    std::string getDescription() const override;

    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override;

    const std::type_info& getValueClass(Settings* settings) const override;

    DataType* clone(DataTypeManager* dtm) const override;

    DataType* copy(DataTypeManager* dtm) const override;

    bool isEquivalent(const DataType* dt) const override;

    int getAlignment() const override;

    std::vector<SettingsDefinition*> getSettingsDefinitions() const override;

    Settings* getDefaultSettings() const override;

    static bool isVoidDataType(const DataType* dt);
};

} // namespace ghidra
