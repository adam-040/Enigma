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

#include <string>
#include <ghidra/Address.h>

namespace ghidra {

class CodeBlock;

/**
 * CodeBlockVertex represents a code block within a graph.
 * Translated from: ghidra.program.model.block.graph.CodeBlockVertex
 */
class CodeBlockVertex {
private:
    CodeBlock* codeBlock_;
    std::string name_;

public:
    explicit CodeBlockVertex(CodeBlock* codeBlock);
    explicit CodeBlockVertex(const std::string& name);

    CodeBlock* getCodeBlock() const { return codeBlock_; }
    std::string getName() const { return name_; }
    bool isDummy() const { return codeBlock_ == nullptr; }

    std::string toString() const { return name_; }

    int compareTo(const CodeBlockVertex& other) const;
    bool equals(const CodeBlockVertex& other) const;
    size_t hash() const;
};

} // namespace ghidra
