/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ObjectPropertyMap.h
/// \brief Property map for Saveable object values
/// Translated from: ghidra.program.model.util.ObjectPropertyMap
#pragma once

#include <ghidra/PropertyMap.h>

namespace ghidra {

class ObjectPropertyMap : public PropertyMapBase {
public:
    virtual void add(const Address& addr, void* value) = 0;
    virtual void* getObject(const Address& addr) const = 0;
};

} // namespace ghidra
