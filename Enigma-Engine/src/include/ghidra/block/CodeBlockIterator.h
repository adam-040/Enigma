/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once

#include <vector>
#include <cstddef>

namespace ghidra {

class CodeBlock;

/**
 * CodeBlockIterator is a forward iterator over CodeBlock objects.
 * Translated from: ghidra.program.model.block.CodeBlockIterator
 */
class CodeBlockIterator {
public:
    CodeBlockIterator() = default;
    virtual ~CodeBlockIterator() = default;
    explicit CodeBlockIterator(const std::vector<CodeBlock*>& blocks);

    bool hasNext() const;
    CodeBlock* next();
    CodeBlock* current() const;
    void reset();
    size_t remaining() const;
    size_t size() const { return blocks_.size(); }

    void addBlock(CodeBlock* block);

private:
    std::vector<CodeBlock*> blocks_;
    size_t index_ = 0;
};

} // namespace ghidra
