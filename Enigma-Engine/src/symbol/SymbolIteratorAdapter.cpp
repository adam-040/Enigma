/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/SymbolIteratorAdapter.h"

namespace ghidra {

SymbolIteratorAdapter::SymbolIteratorAdapter(std::vector<Symbol*> symbols)
    : symbols_(std::move(symbols)), index_(0) {}

SymbolIteratorAdapter::SymbolIteratorAdapter(
    std::vector<Symbol*>::iterator begin,
    std::vector<Symbol*>::iterator end)
    : symbols_(begin, end), index_(0) {}

bool SymbolIteratorAdapter::hasNext() const {
    return index_ < symbols_.size();
}

Symbol* SymbolIteratorAdapter::next() {
    if (!hasNext()) return nullptr;
    return symbols_[index_++];
}

Symbol* SymbolIteratorAdapter::current() const {
    if (index_ == 0 || index_ > symbols_.size()) return nullptr;
    return symbols_[index_ - 1];
}

void SymbolIteratorAdapter::reset() {
    index_ = 0;
}

size_t SymbolIteratorAdapter::remaining() const {
    return symbols_.size() - index_;
}

size_t SymbolIteratorAdapter::size() const {
    return symbols_.size();
}

} // namespace ghidra
