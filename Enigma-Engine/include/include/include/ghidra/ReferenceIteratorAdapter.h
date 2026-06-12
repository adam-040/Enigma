/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ReferenceIteratorAdapter.h
/// \brief Adapter wrapping a Reference iterator to ReferenceIterator
/// Translated from: ghidra.program.model.symbol.ReferenceIteratorAdapter
#pragma once

#include <ghidra/ReferenceIterator.h>
#include <vector>

namespace ghidra {

class ReferenceIteratorAdapter : public ReferenceIterator {
public:
    explicit ReferenceIteratorAdapter(std::vector<Reference*> refs);
    explicit ReferenceIteratorAdapter(std::vector<Reference*>::iterator begin,
                                       std::vector<Reference*>::iterator end);

    bool hasNext() override;
    Reference* next() override;

private:
    std::vector<Reference*> refs_;
    size_t index_ = 0;
};

} // namespace ghidra
