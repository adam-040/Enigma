/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/block/CodeBlockReferenceIterator.h>
#include <ghidra/block/CodeBlockReference.h>

namespace ghidra {

CodeBlockReferenceIterator::CodeBlockReferenceIterator(const std::vector<CodeBlockReference*>& refs)
    : refs_(refs), index_(0) {
}

CodeBlockReference* CodeBlockReferenceIterator::next() {
    if (index_ >= refs_.size()) {
        return nullptr;
    }
    return refs_[index_++];
}

bool CodeBlockReferenceIterator::hasNext() const {
    return index_ < refs_.size();
}

void CodeBlockReferenceIterator::reset() {
    index_ = 0;
}

size_t CodeBlockReferenceIterator::remaining() const {
    return (index_ >= refs_.size()) ? 0 : (refs_.size() - index_);
}

void CodeBlockReferenceIterator::addReference(CodeBlockReference* ref) {
    refs_.push_back(ref);
}

} // namespace ghidra
