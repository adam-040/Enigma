/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataTypeWithCharset.h
/// \brief Interface for DataTypes that have an associated character set.
/// Translated from: ghidra.program.model.data.DataTypeWithCharset
#pragma once

#include "DataType.h"
#include <vector>
#include <cstdint>

namespace ghidra {

class Settings;
class MemBuffer;

/**
 * Interface for DataTypes that have an associated character set.  The default
 * implementation of getCharsetName returns UTF-8; the encode methods throw a
 * DataTypeEncodeException because the full implementation depends on
 * StringDataInstance (not yet ported).
 *
 * Translated from: ghidra.program.model.data.DataTypeWithCharset
 */
class DataTypeWithCharset : public DataType {
public:
    static const std::string DEFAULT_CHARSET_NAME;

    virtual ~DataTypeWithCharset() = default;

    virtual std::string getCharsetName(Settings* settings) const;

    virtual std::vector<uint8_t> encodeCharacterValue(const std::string& value,
                                                      MemBuffer* buf,
                                                      Settings* settings) const;

    virtual std::vector<uint8_t> encodeCharacterRepresentation(const std::string& repr,
                                                                MemBuffer* buf,
                                                                Settings* settings) const;
};

} // namespace ghidra
