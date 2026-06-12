/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataTypeTransferable.h
/// \brief Stub for Java AWT DataTypeTransferable (drag-and-drop, N/A in C++).
#pragma once

#include "ghidra/DataType.h"
#include <string>

namespace ghidra {

class DataTypeTransferable {
    DataType* dataType_;
public:
    DataTypeTransferable(DataType* dt) : dataType_(dt) {}
    DataType* getDataType() const { return dataType_; }
    std::string toString() const { return "DataTypeTransferable"; }
};

} // namespace ghidra
