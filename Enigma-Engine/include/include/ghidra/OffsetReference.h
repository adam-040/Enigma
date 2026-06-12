/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file OffsetReference.h
/// \brief Interface for offset-based memory references
/// Translated from: ghidra.program.model.symbol.OffsetReference
#pragma once

#include <ghidra/Reference.h>

namespace ghidra {

class OffsetReference : public virtual Reference {
public:
    virtual long getOffset() const = 0;
    virtual Address getBaseAddress() const = 0;
};

} // namespace ghidra
