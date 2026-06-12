/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/DirectedGraph.h"
#include <stack>
#include <algorithm>

namespace ghidra {
namespace graph {

bool DirectedGraph::addVertex(const Vertex& v) {
    auto result = vertices_.insert(v);
    if (result.second) {
        adjList_.emplace(v.key(), std::vector<Vertex>());
        predList_.emplace(v.key(), std::vector<Vertex>());
    }
    return result.second;
}

bool DirectedGraph::addEdge(const Edge& e) {
    addVertex(e.from());
    addVertex(e.to());
    auto result = edges_.insert(e);
    if (result.second) {
        adjList_[e.from().key()].push_back(e.to());
        predList_[e.to().key()].push_back(e.from());
    }
    return result.second;
}

bool DirectedGraph::hasVertex(const Vertex& v) const {
    return vertices_.find(v) != vertices_.end();
}

bool DirectedGraph::hasEdge(const Edge& e) const {
    return edges_.find(e) != edges_.end();
}

bool DirectedGraph::removeVertex(const Vertex& v) {
    auto vit = vertices_.find(v);
    if (vit == vertices_.end()) {
        return false;
    }
    int key = v.key();
    std::vector<Edge> toRemove;
    for (const auto& e : edges_) {
        if (e.from() == v || e.to() == v) {
            toRemove.push_back(e);
        }
    }
    for (const auto& e : toRemove) {
        removeEdge(e);
    }
    vertices_.erase(vit);
    adjList_.erase(key);
    predList_.erase(key);
    return true;
}

bool DirectedGraph::removeEdge(const Edge& e) {
    auto eit = edges_.find(e);
    if (eit == edges_.end()) {
        return false;
    }
    int fromKey = e.from().key();
    int toKey = e.to().key();
    auto& succs = adjList_[fromKey];
    succs.erase(std::remove(succs.begin(), succs.end(), e.to()), succs.end());
    auto& preds = predList_[toKey];
    preds.erase(std::remove(preds.begin(), preds.end(), e.from()), preds.end());
    edges_.erase(eit);
    return true;
}

int DirectedGraph::size() const {
    return static_cast<int>(vertices_.size());
}

int DirectedGraph::edgeCount() const {
    return static_cast<int>(edges_.size());
}

std::vector<Vertex> DirectedGraph::getVertices() const {
    std::vector<Vertex> result;
    result.reserve(vertices_.size());
    for (const auto& v : vertices_) {
        result.push_back(v);
    }
    return result;
}

std::vector<Edge> DirectedGraph::getEdges() const {
    std::vector<Edge> result;
    result.reserve(edges_.size());
    for (const auto& e : edges_) {
        result.push_back(e);
    }
    return result;
}

std::vector<Vertex> DirectedGraph::getPredecessors(const Vertex& v) const {
    auto it = predList_.find(v.key());
    if (it != predList_.end()) {
        return it->second;
    }
    return {};
}

std::vector<Vertex> DirectedGraph::getSuccessors(const Vertex& v) const {
    auto it = adjList_.find(v.key());
    if (it != adjList_.end()) {
        return it->second;
    }
    return {};
}

std::vector<Vertex> DirectedGraph::getSources() const {
    std::vector<Vertex> sources;
    for (const auto& v : vertices_) {
        auto it = predList_.find(v.key());
        if (it == predList_.end() || it->second.empty()) {
            sources.push_back(v);
        }
    }
    return sources;
}

std::vector<Vertex> DirectedGraph::getSinks() const {
    std::vector<Vertex> sinks;
    for (const auto& v : vertices_) {
        auto it = adjList_.find(v.key());
        if (it == adjList_.end() || it->second.empty()) {
            sinks.push_back(v);
        }
    }
    return sinks;
}

bool DirectedGraph::containsCycle() const {
    std::unordered_map<int, int> state; // 0=unvisited, 1=in-stack, 2=done
    for (const auto& v : vertices_) {
        state[v.key()] = 0;
    }
    for (const auto& v : vertices_) {
        if (state[v.key()] != 0) continue;
        std::stack<Vertex> stk;
        stk.push(v);
        while (!stk.empty()) {
            Vertex cur = stk.top();
            if (state[cur.key()] == 0) {
                state[cur.key()] = 1;
                for (const auto& succ : getSuccessors(cur)) {
                    if (state[succ.key()] == 1) {
                        return true;
                    }
                    if (state[succ.key()] == 0) {
                        stk.push(succ);
                    }
                }
            } else {
                state[cur.key()] = 2;
                stk.pop();
            }
        }
    }
    return false;
}

} // namespace graph
} // namespace ghidra
