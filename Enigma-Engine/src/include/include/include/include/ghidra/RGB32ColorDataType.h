/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file RGB32ColorDataType.h
/// \brief 32-bit RGB Color data type (default ARGB_8888 encoding).
#pragma once

#include "AbstractColorDataType.h"
#include "RGB32EncodingSettingsDefinition.h"
#include <vector>

namespace ghidra {

class RGB32ColorDataType : public AbstractColorDataType {
public:
    static RGB32ColorDataType dataType;

    static constexpr int LENGTH = 4;

    explicit RGB32ColorDataType(DataTypeManager* dtm = nullptr);

    DataType* clone(DataTypeManager* dtm) const override;

    int getLength() const override;

    std::string getDescription() const override;

    std::string getEncodingName(Settings* settings) const override;

    std::vector<ComponentValue> getComponentValues(MemBuffer* buf, Settings* settings) const override;

    int decodeColor(MemBuffer* buf, Settings* settings) const override;

    std::vector<TypeDefSettingsDefinition*> getTypeDefSettingsDefinitions() const override;
};

} // namespace ghidra
