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
#include <vector>

namespace ghidra {
namespace graph {

class DepthFirstSearch {
public:
    std::vector<Vertex> search(const DirectedGraph& graph, const Vertex& root) const;
    std::vector<Vertex> searchAll(const DirectedGraph& graph) const;
    bool isReachable(const DirectedGraph& graph, const Vertex& start,
                     const Vertex& target) const;
};

} // namespace graph
} // namespace ghidra
