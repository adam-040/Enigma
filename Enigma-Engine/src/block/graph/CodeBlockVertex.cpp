/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/block/graph/CodeBlockVertex.h>
#include <ghidra/block/CodeBlock.h>

namespace ghidra {

CodeBlockVertex::CodeBlockVertex(CodeBlock* codeBlock)
    : codeBlock_(codeBlock), name_(codeBlock->getName()) {
}

CodeBlockVertex::CodeBlockVertex(const std::string& name)
    : codeBlock_(nullptr), name_(name) {
}

int CodeBlockVertex::compareTo(const CodeBlockVertex& other) const {
    if (codeBlock_ == nullptr) {
        return 1;
    }
    if (other.codeBlock_ == nullptr) {
        return -1;
    }
    return codeBlock_->getMinAddress().compareTo(other.codeBlock_->getMinAddress());
}

bool CodeBlockVertex::equals(const CodeBlockVertex& other) const {
    if (codeBlock_ == nullptr && other.codeBlock_ == nullptr) {
        return true;
    }
    if (codeBlock_ == nullptr || other.codeBlock_ == nullptr) {
        return false;
    }
    return codeBlock_->getMinAddress() == other.codeBlock_->getMinAddress();
}

size_t CodeBlockVertex::hash() const {
    if (codeBlock_ == nullptr) {
        return 0;
    }
    return static_cast<size_t>(codeBlock_->getMinAddress().hash());
}

} // namespace ghidra
