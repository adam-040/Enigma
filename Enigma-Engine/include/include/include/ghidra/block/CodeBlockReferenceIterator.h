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

class CodeBlockReference;
class CancelledException;

/**
 * CodeBlockReferenceIterator is a forward iterator over CodeBlockReference objects.
 * Translated from: ghidra.program.model.block.CodeBlockReferenceIterator
 */
class CodeBlockReferenceIterator {
public:
    CodeBlockReferenceIterator() = default;
    explicit CodeBlockReferenceIterator(const std::vector<CodeBlockReference*>& refs);

    virtual ~CodeBlockReferenceIterator() = default;

    virtual CodeBlockReference* next();
    virtual bool hasNext() const;
    void reset();
    size_t remaining() const;
    size_t size() const { return refs_.size(); }

    void addReference(CodeBlockReference* ref);

protected:
    std::vector<CodeBlockReference*> refs_;
    size_t index_ = 0;
};

} // namespace ghidra
