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
#include <ghidra/Edge.h>
#include <vector>
#include <unordered_map>
#include <unordered_set>

namespace ghidra {
namespace graph {

class DirectedGraph {
public:
    bool addVertex(const Vertex& v);
    bool addEdge(const Edge& e);
    bool hasVertex(const Vertex& v) const;
    bool hasEdge(const Edge& e) const;
    bool removeVertex(const Vertex& v);
    bool removeEdge(const Edge& e);
    int size() const;
    int edgeCount() const;

    std::vector<Vertex> getVertices() const;
    std::vector<Edge> getEdges() const;
    std::vector<Vertex> getPredecessors(const Vertex& v) const;
    std::vector<Vertex> getSuccessors(const Vertex& v) const;
    std::vector<Vertex> getSources() const;
    std::vector<Vertex> getSinks() const;
    bool containsCycle() const;

private:
    std::unordered_set<Vertex, Vertex::Hash> vertices_;
    std::unordered_map<int, std::vector<Vertex>> adjList_;
    std::unordered_map<int, std::vector<Vertex>> predList_;
    std::unordered_set<Edge, Edge::Hash> edges_;
};

} // namespace graph
} // namespace ghidra
