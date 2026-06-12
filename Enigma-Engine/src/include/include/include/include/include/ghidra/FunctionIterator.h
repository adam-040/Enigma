/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file FunctionIterator.h
/// \brief Iterator for functions
/// Translated from: ghidra.program.model.listing.FunctionIterator
#pragma once

#include <ghidra/Function.h>
#include <vector>
#include <cstddef>

namespace ghidra {

class FunctionIterator {
public:
    FunctionIterator();
    explicit FunctionIterator(const std::vector<Function*>& functions);

    bool hasNext() const;
    Function* next();
    Function* current() const;
    void reset();
    size_t remaining() const;

private:
    std::vector<Function*> functions_;
    size_t index_ = 0;
};

} // namespace ghidra
