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

#include <ghidra/Vertex.h>
#include <ghidra/DirectedGraph.h>
#include <unordered_map>
#include <vector>

namespace ghidra {
namespace graph {

class Dominator {
public:
    struct Result {
        std::unordered_map<int, int> idom;
    };
    Result computeImmediateDominators(const DirectedGraph& graph,
                                      const Vertex& entry) const;
};

} // namespace graph
} // namespace ghidra
