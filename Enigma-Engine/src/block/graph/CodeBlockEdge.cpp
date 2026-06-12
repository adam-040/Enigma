/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/block/graph/CodeBlockEdge.h>
#include <ghidra/block/graph/CodeBlockVertex.h>

namespace ghidra {

CodeBlockEdge::CodeBlockEdge(CodeBlockVertex* start, CodeBlockVertex* end)
    : start_(start), end_(end) {
}

} // namespace ghidra
