/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file CustomFormat.h
/// \brief Associates a DataType with a raw byte format description
/// Translated from: ghidra.program.model.data.CustomFormat
#pragma once

#include <ghidra/DataType.h>
#include <vector>
#include <cstdint>

namespace ghidra {

class CustomFormat {
private:
    DataType* dataType_;
    std::vector<uint8_t> format_;

public:
    CustomFormat(DataType* dt, const std::vector<uint8_t>& fmt);

    DataType* getDataType() const { return dataType_; }
    const std::vector<uint8_t>& getBytes() const { return format_; }
};

} // namespace ghidra
