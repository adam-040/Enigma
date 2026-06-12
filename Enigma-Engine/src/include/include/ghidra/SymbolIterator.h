/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SymbolIterator.h
/// \brief Iterator for symbols
/// Translated from: ghidra.program.model.symbol.SymbolIterator
#pragma once

#include <ghidra/Symbol.h>
#include <vector>
#include <cstddef>

namespace ghidra {

class SymbolIterator {
public:
    SymbolIterator();
    explicit SymbolIterator(const std::vector<Symbol*>& symbols);

    virtual ~SymbolIterator() = default;

    virtual bool hasNext() const;
    virtual Symbol* next();
    virtual Symbol* current() const;
    virtual void reset();
    virtual size_t remaining() const;
    virtual size_t size() const;

protected:
    std::vector<Symbol*> symbols_;
    size_t index_ = 0;
};

} // namespace ghidra
