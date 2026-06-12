/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file VoidPropertyMap.h
/// \brief Property map for boolean marker values
/// Translated from: ghidra.program.model.util.VoidPropertyMap
#pragma once

#include <ghidra/PropertyMap.h>

namespace ghidra {

class VoidPropertyMap : public PropertyMapBase {
public:
    virtual void add(const Address& addr) = 0;
};

} // namespace ghidra
