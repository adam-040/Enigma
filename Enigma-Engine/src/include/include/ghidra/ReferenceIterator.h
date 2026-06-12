/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ReferenceIterator.h
/// \brief Iterator interface for Reference objects
/// Translated from: ghidra.program.model.symbol.ReferenceIterator
#pragma once

#include <ghidra/Reference.h>

namespace ghidra {

class ReferenceIterator {
public:
    virtual ~ReferenceIterator() = default;
    virtual bool hasNext() = 0;
    virtual Reference* next() = 0;
};

} // namespace ghidra
