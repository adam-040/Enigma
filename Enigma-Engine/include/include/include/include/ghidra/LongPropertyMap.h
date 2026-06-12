/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file LongPropertyMap.h
/// \brief Property map for int64_t values
/// Translated from: ghidra.program.model.util.LongPropertyMap
#pragma once

#include <ghidra/PropertyMap.h>
#include <cstdint>

namespace ghidra {

class LongPropertyMap : public PropertyMapBase {
public:
    virtual void add(const Address& addr, int64_t value) = 0;
    virtual int64_t getLong(const Address& addr) = 0; // throws NoValueException
};

} // namespace ghidra
