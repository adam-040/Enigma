/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/DepthFirstSearch.h"
#include <stack>
#include <unordered_set>

namespace ghidra {
namespace graph {

static std::vector<Vertex> dfsFromRoot(const DirectedGraph& graph, const Vertex& root,
                                        std::unordered_set<int>& visited) {
    std::vector<Vertex> result;
    std::stack<Vertex> stk;
    stk.push(root);
    visited.insert(root.key());
    while (!stk.empty()) {
        Vertex v = stk.top();
        stk.pop();
        result.push_back(v);
        auto succs = graph.getSuccessors(v);
        for (auto it = succs.rbegin(); it != succs.rend(); ++it) {
            if (visited.find(it->key()) == visited.end()) {
                visited.insert(it->key());
                stk.push(*it);
            }
        }
    }
    return result;
}

std::vector<Vertex> DepthFirstSearch::search(const DirectedGraph& graph,
                                              const Vertex& root) const {
    std::unordered_set<int> visited;
    return dfsFromRoot(graph, root, visited);
}

std::vector<Vertex> DepthFirstSearch::searchAll(const DirectedGraph& graph) const {
    std::vector<Vertex> result;
    std::unordered_set<int> visited;
    auto sources = graph.getSources();
    if (sources.empty()) {
        auto verts = graph.getVertices();
        if (!verts.empty()) {
            sources.push_back(verts[0]);
        }
    }
    for (const auto& root : sources) {
        if (visited.find(root.key()) == visited.end()) {
            auto part = dfsFromRoot(graph, root, visited);
            result.insert(result.end(), part.begin(), part.end());
        }
    }
    return result;
}

bool DepthFirstSearch::isReachable(const DirectedGraph& graph, const Vertex& start,
                                    const Vertex& target) const {
    std::unordered_set<int> visited;
    std::stack<Vertex> stk;
    stk.push(start);
    visited.insert(start.key());
    while (!stk.empty()) {
        Vertex v = stk.top();
        stk.pop();
        if (v == target) {
            return true;
        }
        auto succs = graph.getSuccessors(v);
        for (auto it = succs.rbegin(); it != succs.rend(); ++it) {
            if (visited.find(it->key()) == visited.end()) {
                visited.insert(it->key());
                stk.push(*it);
            }
        }
    }
    return false;
}

} // namespace graph
} // namespace ghidra
