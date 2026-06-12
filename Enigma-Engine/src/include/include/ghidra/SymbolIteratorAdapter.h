/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SymbolIteratorAdapter.h
/// \brief Adapter wrapping a vector of symbols into SymbolIterator.
/// Translated from: ghidra.program.model.symbol.SymbolIteratorAdapter
#pragma once

#include <ghidra/SymbolIterator.h>
#include <vector>

namespace ghidra {

class SymbolIteratorAdapter : public SymbolIterator {
public:
    SymbolIteratorAdapter() = default;
    explicit SymbolIteratorAdapter(std::vector<Symbol*> symbols);

    SymbolIteratorAdapter(std::vector<Symbol*>::iterator begin,
                          std::vector<Symbol*>::iterator end);

    bool hasNext() const override;
    Symbol* next() override;
    Symbol* current() const override;
    void reset() override;
    size_t remaining() const override;
    size_t size() const override;

private:
    std::vector<Symbol*> symbols_;
    size_t index_ = 0;
};

} // namespace ghidra
