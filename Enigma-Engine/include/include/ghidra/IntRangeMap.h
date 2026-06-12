/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file IntRangeMap.h
/// \brief Integer range map interface
/// Translated from: ghidra.program.database.IntRangeMap
#pragma once

#include <ghidra/Address.h>
#include <cstdint>

namespace ghidra {

class IntRangeMap {
public:
    virtual ~IntRangeMap() = default;

    virtual const std::string& getName() const = 0;
    virtual int64_t getValue(Address addr) = 0;
    virtual void setValue(Address start, Address end, int64_t value) = 0;
    virtual void clearValue(Address start, Address end) = 0;
};

} // namespace ghidra
