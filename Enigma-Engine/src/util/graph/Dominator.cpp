/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/Dominator.h"
#include <stack>
#include <algorithm>
#include <limits>

namespace ghidra {
namespace graph {

Dominator::Result Dominator::computeImmediateDominators(const DirectedGraph& graph,
                                                         const Vertex& entry) const {
    Result result;

    if (!graph.hasVertex(entry)) {
        return result;
    }

    auto verts = graph.getVertices();
    int n = static_cast<int>(verts.size());
    if (n == 0) {
        return result;
    }

    // DFS numbering (1-based)
    std::unordered_map<int, int> dfn;
    std::unordered_map<int, int> vertexByDfn;
    std::unordered_map<int, int> parent;

    // Initialize
    for (const auto& v : verts) {
        dfn[v.key()] = 0;
    }

    // DFS from entry
    int counter = 0;
    std::stack<Vertex> stk;
    stk.push(entry);
    dfn[entry.key()] = ++counter;
    vertexByDfn[counter] = entry.key();
    parent[entry.key()] = -1;

    while (!stk.empty()) {
        Vertex v = stk.top();
        bool hasUnvisited = false;
        auto succs = graph.getSuccessors(v);
        for (const auto& s : succs) {
            if (dfn[s.key()] == 0) {
                dfn[s.key()] = ++counter;
                vertexByDfn[counter] = s.key();
                parent[s.key()] = v.key();
                stk.push(s);
                hasUnvisited = true;
                break;
            }
        }
        if (!hasUnvisited) {
            stk.pop();
        }
    }

    // Handle unreachable vertices
    for (const auto& v : verts) {
        if (dfn[v.key()] == 0) {
            result.idom[v.key()] = -1;
        }
    }

    int dfsCount = counter;
    if (dfsCount == 0) {
        return result;
    }

    // Lengauer-Tarjan data structures
    std::unordered_map<int, int> semi;
    std::unordered_map<int, int> idom;
    std::unordered_map<int, int> ancestor;
    std::unordered_map<int, int> best;
    std::unordered_map<int, std::vector<int>> bucket;

    for (int i = 1; i <= dfsCount; i++) {
        int vk = vertexByDfn[i];
        semi[vk] = vk;
        idom[vk] = -1;
        ancestor[vk] = -1;
        best[vk] = vk;
    }

    auto compress = [&](int vk, auto& compress_ref) -> void {
        if (ancestor[ancestor[vk]] != -1) {
            compress_ref(ancestor[vk], compress_ref);
            if (dfn[semi[best[ancestor[vk]]]] < dfn[semi[best[vk]]]) {
                best[vk] = best[ancestor[vk]];
            }
            ancestor[vk] = ancestor[ancestor[vk]];
        }
    };

    auto evalFn = [&](int vk) -> int {
        if (ancestor[vk] == -1) {
            return vk;
        }
        compress(vk, compress);
        if (dfn[semi[best[ancestor[vk]]]] >= dfn[semi[best[vk]]]) {
            return best[vk];
        }
        return best[ancestor[vk]];
    };

    auto linkFn = [&](int vk, int wk) -> void {
        ancestor[wk] = vk;
        best[wk] = wk;
    };

    // Reverse DFS order
    for (int i = dfsCount; i >= 2; i--) {
        int wk = vertexByDfn[i];
        int parentW = parent[wk];

        // Compute semi-dominator
        auto preds = graph.getPredecessors(Vertex(wk));
        for (const auto& p : preds) {
            int pKey = p.key();
            if (dfn[pKey] == 0) continue;
            int u = evalFn(pKey);
            if (dfn[semi[u]] < dfn[semi[wk]]) {
                semi[wk] = semi[u];
            }
        }

        bucket[semi[wk]].push_back(wk);
        linkFn(parentW, wk);

        // Compute immediate dominators from buckets
        auto& bs = bucket[parentW];
        for (int vk : bs) {
            int u = evalFn(vk);
            if (dfn[semi[u]] < dfn[semi[vk]]) {
                idom[vk] = u;
            } else {
                idom[vk] = parentW;
            }
        }
        bs.clear();
    }

    // Final pass
    for (int i = 2; i <= dfsCount; i++) {
        int wk = vertexByDfn[i];
        if (idom[wk] != semi[wk]) {
            idom[wk] = idom[idom[wk]];
        }
        result.idom[wk] = idom[wk];
    }

    // Entry has no immediate dominator
    result.idom[entry.key()] = -1;

    return result;
}

} // namespace graph
} // namespace ghidra
