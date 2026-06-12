/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ShiftedReference.h
/// \brief Interface for shifted memory references
/// Translated from: ghidra.program.model.symbol.ShiftedReference
#pragma once

#include <ghidra/Reference.h>

namespace ghidra {

class ShiftedReference : public virtual Reference {
public:
    virtual int getShift() const = 0;
    virtual long getValue() const = 0;
};

} // namespace ghidra
