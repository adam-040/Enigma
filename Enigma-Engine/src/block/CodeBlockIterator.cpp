/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/block/CodeBlockIterator.h>
#include <ghidra/block/CodeBlock.h>

namespace ghidra {

CodeBlockIterator::CodeBlockIterator(const std::vector<CodeBlock*>& blocks)
    : blocks_(blocks), index_(0) {
}

bool CodeBlockIterator::hasNext() const {
    return index_ < blocks_.size();
}

CodeBlock* CodeBlockIterator::next() {
    if (index_ >= blocks_.size()) {
        return nullptr;
    }
    return blocks_[index_++];
}

CodeBlock* CodeBlockIterator::current() const {
    if (index_ == 0 || index_ > blocks_.size()) {
        return nullptr;
    }
    return blocks_[index_ - 1];
}

void CodeBlockIterator::reset() {
    index_ = 0;
}

size_t CodeBlockIterator::remaining() const {
    return (index_ >= blocks_.size()) ? 0 : (blocks_.size() - index_);
}

void CodeBlockIterator::addBlock(CodeBlock* block) {
    blocks_.push_back(block);
}

} // namespace ghidra
