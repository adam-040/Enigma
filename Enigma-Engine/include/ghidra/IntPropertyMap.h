/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file IntPropertyMap.h
/// \brief Property map for int32_t values
/// Translated from: ghidra.program.model.util.IntPropertyMap
#pragma once

#include <ghidra/PropertyMap.h>
#include <cstdint>

namespace ghidra {

class IntPropertyMap : public PropertyMapBase {
public:
    virtual void add(const Address& addr, int32_t value) = 0;
    virtual int32_t getInt(const Address& addr) = 0; // throws NoValueException
};

} // namespace ghidra
