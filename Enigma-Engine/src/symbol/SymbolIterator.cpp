/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SymbolIterator.cpp
/// \brief Symbol iterator implementation
#include <ghidra/SymbolIterator.h>

namespace ghidra {

SymbolIterator::SymbolIterator() = default;

SymbolIterator::SymbolIterator(const std::vector<Symbol*>& symbols)
    : symbols_(symbols), index_(0) {}

bool SymbolIterator::hasNext() const {
    return index_ < symbols_.size();
}

Symbol* SymbolIterator::next() {
    if (!hasNext()) return nullptr;
    return symbols_[index_++];
}

Symbol* SymbolIterator::current() const {
    if (index_ == 0 || index_ > symbols_.size()) return nullptr;
    return symbols_[index_ - 1];
}

void SymbolIterator::reset() {
    index_ = 0;
}

size_t SymbolIterator::remaining() const {
    return symbols_.size() - index_;
}

size_t SymbolIterator::size() const {
    return symbols_.size();
}

} // namespace ghidra
