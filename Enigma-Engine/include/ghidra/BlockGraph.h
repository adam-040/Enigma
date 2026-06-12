#pragma once

#include <ghidra/PcodeBlockBasic.h>
#include <vector>
#include <set>

namespace ghidra {

class BlockGraph {
public:
    std::vector<PcodeBlockBasic*> blocks;
    std::vector<PcodeBlockEdge*> edges;
    int num = 0;
    int startnode = 0;

    BlockGraph() = default;
    ~BlockGraph();

    PcodeBlockBasic* addBlock();
    PcodeBlockEdge* addEdge(PcodeBlockBasic* src, PcodeBlockBasic* dest, int flags = 0);
    void removeBlock(int index);
    void clear();
    PcodeBlockBasic* getBlock(int index) const;
    int getNumBlocks() const { return num; }
    int getNumEdges() const { return static_cast<int>(edges.size()); }
    int getStartNode() const { return startnode; }
    void setStartNode(int idx) { startnode = idx; }

    // Dominator analysis
    void computeDominators();
    void computePostDominators();
    int getDominator(int blockIndex) const;
    int getPostDominator(int blockIndex) const;
    const std::set<int>& getDominanceFrontier(int blockIndex) const;
    const std::vector<int>& getDominatorTreeChildren(int blockIndex) const;

private:
    // Dominator data (filled by computeDominators)
    std::vector<int> idom_;                       // immediate dominator (-1 = none)
    std::vector<int> ipostdom_;                   // immediate post-dominator (-1 = none)
    std::vector<std::set<int>> domFrontier_;      // dominance frontier per block
    std::vector<std::vector<int>> domChildren_;   // dominator tree children

    void computeDominatorsInternal(bool reverse);
    void computeDominanceFrontiers();
};

} // namespace ghidra
