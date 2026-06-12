/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataTypeWithCharset.cpp
#include "ghidra/DataTypeWithCharset.h"
#include "ghidra/MemBuffer.h"
#include "ghidra/Settings.h"

namespace ghidra {

const std::string DataTypeWithCharset::DEFAULT_CHARSET_NAME = "UTF-8";

std::string DataTypeWithCharset::getCharsetName(Settings* settings) const {
    return DEFAULT_CHARSET_NAME;
}

std::vector<uint8_t> DataTypeWithCharset::encodeCharacterValue(const std::string& value,
                                                              MemBuffer* buf,
                                                              Settings* settings) const {
    throw DataTypeEncodeException(
        std::string("encodeCharacterValue requires StringDataInstance (not yet ported): ") + value);
}

std::vector<uint8_t> DataTypeWithCharset::encodeCharacterRepresentation(const std::string& repr,
                                                                        MemBuffer* buf,
                                                                        Settings* settings) const {
    throw DataTypeEncodeException(
        std::string("encodeCharacterRepresentation requires StringDataInstance (not yet ported): ") + repr);
}

} // namespace ghidra
