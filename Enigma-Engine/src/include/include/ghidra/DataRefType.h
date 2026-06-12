/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataRefType.h
/// \brief Reference types for data.
/// Translated from: ghidra.program.model.symbol.DataRefType
#pragma once

#include <ghidra/RefType.h>

namespace ghidra {

class DataRefType : public RefType {
public:
    static constexpr int READX  = 1;
    static constexpr int WRITEX = 2;
    static constexpr int INDX   = 4;

    DataRefType(int8_t type, const std::string& name, int access)
        : RefType(type, name), access_(access) {}

    bool isData() const override { return true; }
    bool isRead() const override { return (access_ & READX) != 0; }
    bool isWrite() const override { return (access_ & WRITEX) != 0; }
    bool isIndirect() const override { return (access_ & INDX) != 0; }

private:
    int access_;
};

} // namespace ghidra
