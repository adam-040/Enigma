/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file FunctionIterator.cpp
/// \brief Function iterator implementation
#include <ghidra/FunctionIterator.h>

namespace ghidra {

FunctionIterator::FunctionIterator() = default;

FunctionIterator::FunctionIterator(const std::vector<Function*>& functions)
    : functions_(functions), index_(0) {}

bool FunctionIterator::hasNext() const {
    return index_ < functions_.size();
}

Function* FunctionIterator::next() {
    if (!hasNext()) return nullptr;
    return functions_[index_++];
}

Function* FunctionIterator::current() const {
    if (index_ == 0 || index_ > functions_.size()) return nullptr;
    return functions_[index_ - 1];
}

void FunctionIterator::reset() {
    index_ = 0;
}

size_t FunctionIterator::remaining() const {
    return functions_.size() - index_;
}

} // namespace ghidra
