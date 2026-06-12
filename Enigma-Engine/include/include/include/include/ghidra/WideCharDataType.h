/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file WideCharDataType.h
/// \brief Wide-Character (compiler-specific size) data type.
/// Translated from: ghidra.program.model.data.WideCharDataType
#pragma once

#include "BuiltIn.h"
#include "CharsetInfoManager.h"
#include <cstdint>
#include <string>
#include <vector>

namespace ghidra {

class MemBuffer;
class Settings;
class SettingsDefinition;
class DataTypeDisplayOptions;
class DataTypeManager;

/**
 * Wide-Character (compiler-specific size) data type.  The actual byte size is
 * determined by the data organization; defaults to 2 bytes when the size is
 * not specified.
 *
 * Translated from: ghidra.program.model.data.WideCharDataType
 */
class WideCharDataType : public BuiltIn {
public:
    static WideCharDataType& dataType();

    WideCharDataType(DataTypeManager* dtm = nullptr);

    DataType* clone(DataTypeManager* dtm) const override;

    int getLength() const override;
    bool hasLanguageDependantLength() const override { return true; }
    std::string getDescription() const override;
    std::string getMnemonic(Settings* settings) const override;
    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override;
    std::string getDefaultLabelPrefix() const override;
    std::string getDefaultLabelPrefix(MemBuffer* buf, Settings* settings, int length,
                                       DataTypeDisplayOptions* options) const override;
    std::vector<SettingsDefinition*> getSettingsDefinitions() const override;
    const std::type_info& getValueClass(Settings* settings) const override;
    bool isEncodable() const override { return true; }
    std::vector<uint8_t> encodeValue(void* value, MemBuffer* buf, Settings* settings,
                                      int length) const;
    std::vector<uint8_t> encodeRepresentation(const std::string& repr, MemBuffer* buf,
                                                Settings* settings, int length) const;
    std::string getCharsetName(Settings* settings) const;
    bool hasStringValue(Settings* settings) const;
    std::string getArrayDefaultLabelPrefix(MemBuffer* buf, Settings* settings, int len,
                                            const DataTypeDisplayOptions& options) const;
    std::string getArrayDefaultOffcutLabelPrefix(MemBuffer* buf, Settings* settings, int len,
                                                  const DataTypeDisplayOptions& options,
                                                  int offcutLength) const;
};

} // namespace ghidra
