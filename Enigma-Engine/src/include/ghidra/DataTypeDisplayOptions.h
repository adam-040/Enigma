/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataTypeDisplayOptions.h
/// \brief Display options for data types
/// Translated from: ghidra.program.model.data.DataTypeDisplayOptions
#pragma once

namespace ghidra {

/**
 * Display options for data types (label length, abbreviated form).
 *
 * Translated from: ghidra.program.model.data.DataTypeDisplayOptions
 */
class DataTypeDisplayOptions {
public:
    static const int MAX_LABEL_STRING_LENGTH = 32;

    virtual ~DataTypeDisplayOptions() = default;

    virtual int getLabelStringLength() const = 0;
    virtual bool useAbbreviatedForm() const = 0;

    static const DataTypeDisplayOptions& DEFAULT();
};

} // namespace ghidra
