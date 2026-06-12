/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file EquateReference.h
/// \brief Interface for equate references
/// Translated from: ghidra.program.model.symbol.EquateReference
#pragma once

#include <ghidra/Address.h>
#include <cstdint>

namespace ghidra {

class EquateReference {
public:
    virtual ~EquateReference() = default;

    virtual Address getAddress() const = 0;
    virtual int16_t getOpIndex() const = 0;
    virtual int64_t getDynamicHashValue() const = 0;
};

} // namespace ghidra
