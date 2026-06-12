/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/ReferenceIteratorAdapter.h"

namespace ghidra {

ReferenceIteratorAdapter::ReferenceIteratorAdapter(std::vector<Reference*> refs)
    : refs_(std::move(refs)), index_(0) {}

ReferenceIteratorAdapter::ReferenceIteratorAdapter(
    std::vector<Reference*>::iterator begin,
    std::vector<Reference*>::iterator end)
    : refs_(begin, end), index_(0) {}

bool ReferenceIteratorAdapter::hasNext() {
    return index_ < refs_.size();
}

Reference* ReferenceIteratorAdapter::next() {
    if (!hasNext()) return nullptr;
    return refs_[index_++];
}

} // namespace ghidra
