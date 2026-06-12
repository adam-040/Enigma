/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file RGB16ColorDataType.h
/// \brief 16-bit RGB Color data type (default RGB_565 encoding).
#pragma once

#include "AbstractColorDataType.h"
#include "RGB16EncodingSettingsDefinition.h"
#include <vector>

namespace ghidra {

class RGB16ColorDataType : public AbstractColorDataType {
public:
    static RGB16ColorDataType dataType;

    static constexpr int LENGTH = 2;

    explicit RGB16ColorDataType(DataTypeManager* dtm = nullptr);

    DataType* clone(DataTypeManager* dtm) const override;

    int getLength() const override;

    std::string getDescription() const override;

    std::string getEncodingName(Settings* settings) const override;

    std::vector<ComponentValue> getComponentValues(MemBuffer* buf, Settings* settings) const override;

    int decodeColor(MemBuffer* buf, Settings* settings) const override;

    std::vector<TypeDefSettingsDefinition*> getTypeDefSettingsDefinitions() const override;
};

} // namespace ghidra
