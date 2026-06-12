#include <ghidra/BlockGraph.h>
#include <algorithm>
#include <cstring>
#include <limits>

namespace ghidra {

BlockGraph::~BlockGraph() {
    for (auto* edge : edges) delete edge;
    for (auto* block : blocks) delete block;
}

PcodeBlockBasic* BlockGraph::addBlock() {
    auto* block = new PcodeBlockBasic();
    blocks.push_back(block);
    num++;
    return block;
}

PcodeBlockEdge* BlockGraph::addEdge(PcodeBlockBasic* src, PcodeBlockBasic* dest, int flags) {
    auto* edge = new PcodeBlockEdge(src, dest, flags);
    edges.push_back(edge);
    src->addOutEdge(edge);
    dest->addInEdge(edge);
    return edge;
}

void BlockGraph::removeBlock(int index) {
    if (index >= 0 && index < num) {
        auto* block = blocks[index];
        for (auto it = edges.begin(); it != edges.end(); ) {
            if ((*it)->src == block || (*it)->dest == block) {
                delete *it;
                it = edges.erase(it);
            } else {
                ++it;
            }
        }
        delete block;
        blocks.erase(blocks.begin() + index);
        num--;
    }
}

void BlockGraph::clear() {
    for (auto* edge : edges) delete edge;
    edges.clear();
    for (auto* block : blocks) delete block;
    blocks.clear();
    num = 0;
}

PcodeBlockBasic* BlockGraph::getBlock(int index) const {
    if (index >= 0 && index < num) return blocks[index];
    return nullptr;
}

// ========== Lengauer-Tarjan Dominator Algorithm ==========

void BlockGraph::computeDominators() {
    computeDominatorsInternal(false);
}

void BlockGraph::computePostDominators() {
    computeDominatorsInternal(true);
}

int BlockGraph::getDominator(int blockIndex) const {
    if (blockIndex < 0 || blockIndex >= static_cast<int>(idom_.size())) return -1;
    return idom_[blockIndex];
}

int BlockGraph::getPostDominator(int blockIndex) const {
    if (blockIndex < 0 || blockIndex >= static_cast<int>(ipostdom_.size())) return -1;
    return ipostdom_[blockIndex];
}

const std::set<int>& BlockGraph::getDominanceFrontier(int blockIndex) const {
    static std::set<int> emptySet;
    if (blockIndex < 0 || blockIndex >= static_cast<int>(domFrontier_.size())) return emptySet;
    return domFrontier_[blockIndex];
}

const std::vector<int>& BlockGraph::getDominatorTreeChildren(int blockIndex) const {
    static std::vector<int> emptyVec;
    if (blockIndex < 0 || blockIndex >= static_cast<int>(domChildren_.size())) return emptyVec;
    return domChildren_[blockIndex];
}

void BlockGraph::computeDominatorsInternal(bool reverse) {
    int n = num;
    if (n == 0) return;

    std::vector<int>& result = reverse ? ipostdom_ : idom_;
    result.assign(n, -1);
    domFrontier_.resize(n);
    domChildren_.resize(n);

    int root = reverse ? -1 : startnode;
    if (reverse) {
        // Find exit node (block with 0 outgoing edges) as root for post-dominators
        for (int i = 0; i < n; i++) {
            if (blocks[i]->getOutSize() == 0) { root = i; break; }
        }
    }
    if (root < 0) return;

    // Helper: get successors or predecessors based on direction
    auto getNeighbors = [this, reverse](int idx, std::vector<int>& out) {
        PcodeBlockBasic* block = blocks[idx];
        if (!block) return;
        int sz = reverse ? block->getInSize() : block->getOutSize();
        for (int i = 0; i < sz; i++) {
            PcodeBlockBasic* nb = reverse ? block->getIn(i) : block->getOut(i);
            if (!nb) continue;
            int nidx = -1;
            for (int j = 0; j < num; j++) {
                if (blocks[j] == nb) { nidx = j; break; }
            }
            if (nidx >= 0) out.push_back(nidx);
        }
    };

    // Reachability DFS in the appropriate direction
    std::vector<bool> reachable(n, false);
    std::vector<int> dfsOrder;
    {
        std::vector<int> stack;
        stack.push_back(root);
        reachable[root] = true;
        while (!stack.empty()) {
            int v = stack.back();
            stack.pop_back();
            dfsOrder.push_back(v);
            std::vector<int> nbrs;
            getNeighbors(v, nbrs);
            for (int nv : nbrs) {
                if (!reachable[nv]) {
                    reachable[nv] = true;
                    stack.push_back(nv);
                }
            }
        }
    }

    // Reverse topological order for convergence
    std::vector<int> revOrder;
    {
        std::vector<bool> visited(n, false);
        std::vector<int> stack;
        stack.push_back(root);
        while (!stack.empty()) {
            int v = stack.back();
            stack.pop_back();
            if (visited[v]) continue;
            visited[v] = true;
            revOrder.push_back(v);
            std::vector<int> nbrs;
            getNeighbors(v, nbrs);
            for (int nv : nbrs) {
                if (!visited[nv]) stack.push_back(nv);
            }
        }
        std::reverse(revOrder.begin(), revOrder.end());
    }

    // Iterative data-flow dominator computation
    // dom(b) = {b} ∪ ∩_{p ∈ pred(b)} dom(p)
    // For reverse (post-dominators), "pred" = successors
    std::vector<std::vector<int>> dom(n);

    dom[root] = {root};
    for (int i = 0; i < n; i++) {
        if (i != root && reachable[i]) {
            dom[i].resize(n);
            for (int j = 0; j < n; j++) dom[i][j] = j;
        }
    }

    bool changed = true;
    while (changed) {
        changed = false;
        for (int wi : revOrder) {
            if (wi == root || !reachable[wi]) continue;

            PcodeBlockBasic* wblock = blocks[wi];
            std::vector<bool> intersect(n, true);
            bool hasPred = false;

            // For forward: predecessors are blocks with edges into wi
            // For reverse: predecessors (in dominator sense) are successors of wi
            for (int i = 0; i < (reverse ? wblock->getOutSize() : wblock->getInSize()); i++) {
                PcodeBlockBasic* pblock = reverse ? wblock->getOut(i) : wblock->getIn(i);
                if (!pblock) continue;
                int pidx = -1;
                for (int j = 0; j < n; j++) {
                    if (blocks[j] == pblock) { pidx = j; break; }
                }
                if (pidx < 0 || !reachable[pidx]) continue;
                hasPred = true;
                std::vector<bool> predDom(n, false);
                for (int d : dom[pidx]) predDom[d] = true;
                for (int j = 0; j < n; j++) {
                    if (!predDom[j]) intersect[j] = false;
                }
            }

            if (!hasPred) continue;

            std::vector<int> newDom;
            newDom.push_back(wi);
            for (int j = 0; j < n; j++) {
                if (intersect[j] && j != wi) newDom.push_back(j);
            }

            if (newDom.size() != dom[wi].size()) {
                changed = true;
                dom[wi] = newDom;
            } else {
                std::vector<int> oldSorted = dom[wi];
                std::vector<int> newSorted = newDom;
                std::sort(oldSorted.begin(), oldSorted.end());
                std::sort(newSorted.begin(), newSorted.end());
                if (oldSorted != newSorted) {
                    changed = true;
                    dom[wi] = newDom;
                }
            }
        }
    }

    // Compute immediate dominators from full dom sets
    for (int i = 0; i < n; i++) {
        if (i == root || !reachable[i]) continue;
        const auto& domSet = dom[i];
        int best = -1;
        size_t bestSize = 0;
        for (int d : domSet) {
            if (d == i) continue;
            if (dom[d].size() > bestSize) {
                bestSize = dom[d].size();
                best = d;
            }
        }
        result[i] = best;
    }

    // Build dominator tree children
    domChildren_.resize(n);
    for (int i = 0; i < n; i++) {
        if (result[i] >= 0 && result[i] < n) {
            domChildren_[result[i]].push_back(i);
        }
    }

    computeDominanceFrontiers();
}

void BlockGraph::computeDominanceFrontiers() {
    int n = num;
    for (int i = 0; i < n; i++) {
        domFrontier_[i].clear();
    }

    // For each node, check if it's not immediately dominated by its predecessors
    for (int i = 0; i < n; i++) {
        PcodeBlockBasic* block = blocks[i];
        if (block->getInSize() < 2) continue;

        for (int j = 0; j < block->getInSize(); j++) {
            PcodeBlockBasic* predBlock = block->getIn(j);
            if (!predBlock) continue;
            int predIdx = -1;
            for (int k = 0; k < n; k++) {
                if (blocks[k] == predBlock) { predIdx = k; break; }
            }
            if (predIdx < 0) continue;

            // Walk up the dominator tree from pred until we reach i's immediate dominator
            int runner = predIdx;
            while (runner >= 0 && runner != idom_[i]) {
                domFrontier_[runner].insert(i);
                runner = idom_[runner];
            }
        }
    }
}

} // namespace ghidra
