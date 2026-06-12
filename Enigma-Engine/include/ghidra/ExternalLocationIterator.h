/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ExternalLocationIterator.h
/// \brief Iterator interface for external locations
/// Translated from: ghidra.program.model.symbol.ExternalLocationIterator
#pragma once

#include <ghidra/ExternalManager.h>

namespace ghidra {

class ExternalLocationIterator {
public:
    virtual ~ExternalLocationIterator() = default;
    virtual bool hasNext() = 0;
    virtual ExternalLocation* next() = 0;
};

} // namespace ghidra
