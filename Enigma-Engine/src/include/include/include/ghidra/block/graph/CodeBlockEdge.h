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

namespace ghidra {

class CodeBlockVertex;

/**
 * CodeBlockEdge represents a link between two CodeBlock vertices.
 * Translated from: ghidra.program.model.block.graph.CodeBlockEdge
 */
class CodeBlockEdge {
private:
    CodeBlockVertex* start_;
    CodeBlockVertex* end_;

public:
    CodeBlockEdge(CodeBlockVertex* start, CodeBlockVertex* end);

    CodeBlockVertex* getStart() const { return start_; }
    CodeBlockVertex* getEnd() const { return end_; }
};

} // namespace ghidra
