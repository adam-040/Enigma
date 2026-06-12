/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ArrayStringable.h
/// \brief Interface for DataTypes that, when formed into an array, can be
///        interpreted as a string.
/// Translated from: ghidra.program.model.data.ArrayStringable
#pragma once

#include "DataType.h"
#include <string>

namespace ghidra {

class Settings;
class MemBuffer;
class DataTypeDisplayOptions;

/**
 * Identifies data types which when formed into an array can be interpreted as
 * a string (e.g., character array).  The Array implementations use this
 * interface as both a marker and to generate appropriate representations and
 * values for data instances.
 *
 * Translated from: ghidra.program.model.data.ArrayStringable
 */
class ArrayStringable : public DataType {
public:
    virtual ~ArrayStringable() = default;

    virtual bool hasStringValue(Settings* settings) const = 0;

    virtual std::string getArrayString(MemBuffer* buf, Settings* settings, int length) const;

    virtual std::string getArrayDefaultLabelPrefix(MemBuffer* buf, Settings* settings, int len,
                                                   const DataTypeDisplayOptions* options) const = 0;

    virtual std::string getArrayDefaultOffcutLabelPrefix(MemBuffer* buf, Settings* settings,
                                                         int len,
                                                         const DataTypeDisplayOptions* options,
                                                         int offcutLength) const = 0;

    static ArrayStringable* getArrayStringable(const DataType* dt);
};

} // namespace ghidra
