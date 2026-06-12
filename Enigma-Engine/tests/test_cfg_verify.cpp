// Quick live CFG verification check for Component 3 sign-off.
// Compile and run demonstrating FlowInfo generating blocks,
// edges, and dominance frontiers without truncation or early returns.

#include <ghidra/AddressSpace.h>
#include <ghidra/Address.h>
#include <ghidra/Funcdata.h>
#include <ghidra/FlowInfo.h>
#include <ghidra/FuncCallSpecs.h>
#include <ghidra/PcodeOpAST.h>
#include <ghidra/Varnode.h>
#include <ghidra/PcodeBlockBasic.h>
#include <ghidra/BlockGraph.h>
#include <vector>
#include <cstdio>
#include <set>
#include <cassert>

int main() {
    using namespace ghidra;

    // Create address spaces matching the functional test environment
    GenericAddressSpace w51Space("w51", 51, AddressSpace::TYPE_RAM, 0);
    GenericAddressSpace cfgConst("const", 64, AddressSpace::TYPE_CONSTANT, 0);

    // --- TEST: Branch + Merge CFG ---
    // Layout:  B0: BRANCH target=0x1002   B1: BRANCH target=0x1004   B2: (merge target)
    //          B3: (exit)
    // Edges: B0->B2, B1->B2, B2->B3

    Funcdata fd("CFG_verify", Address(&w51Space, 0x1000));

    // A0: BRANCH target=A2 (0x1002)
    auto* op0 = fd.createOp(Address(&w51Space, 0x1000), PcodeOp::BRANCH, 1);
    auto* tgt0 = fd.createVarnode(Address(&cfgConst, 0x1002), 4, 10);
    op0->setInput(tgt0, 0);

    // A1: BRANCH target=A2 (0x1002) — merges into same block
    auto* op1 = fd.createOp(Address(&w51Space, 0x1001), PcodeOp::BRANCH, 1);
    auto* tgt1 = fd.createVarnode(Address(&cfgConst, 0x1002), 4, 11);
    op1->setInput(tgt1, 0);

    // A2: COPY — merge target
    fd.createOp(Address(&w51Space, 0x1002), PcodeOp::COPY, 1);

    // A3: COPY — exit
    fd.createOp(Address(&w51Space, 0x1003), PcodeOp::COPY, 1);

    // Place all ops into a single initial block (as Sleigh would)
    auto* block = fd.getBlockGraph()->addBlock();
    for (int i = 0; i < fd.getNumOps(); i++) {
        block->insertEnd(fd.getOp(i));
    }
    block->rebuildCoverFromOps();

    // Verify initial state
    assert(block->getFirstOp() != nullptr && "First op must exist");
    assert(block->getLastOp() != nullptr && "Last op must exist");
    assert(fd.getBlockGraph()->getNumBlocks() == 1 && "Start with 1 block");
    printf("[PASS] Initial state: 1 block with %d ops\n", fd.getNumOps());

    // Run FlowInfo CFG construction
    std::vector<FuncCallSpecs*> callList;
    FlowInfo fi(fd, *fd.getBlockGraph(), callList);
    fi.generateOps();
    fi.generateBlocks();

    // --- Verification Block ---
    BlockGraph* bg = fd.getBlockGraph();
    int numBlocks = bg->getNumBlocks();
    int numEdges = bg->getNumEdges();

    printf("\n=== Live CFG Verification ===\n");
    printf("Blocks: %d\n", numBlocks);
    printf("Edges: %d\n", numEdges);

    // Expected: 3 blocks.
    // B0=[BRANCH@0x1000], B1=[BRANCH@0x1001], B2=[COPY@0x1002, COPY@0x1003]
    // The two BRANCH ops are terminators so they each get their own block.
    // B2 is a merge+exit (COPY is non-terminal, no fallthrough since it is last).
    assert(numBlocks == 3 && "Must produce 3 blocks: B0(0x1000) B1(0x1001) B2(0x1002+0x1003)");
    printf("[PASS] Block count correct: 3\n");

    // Verify each block's properties
    for (int i = 0; i < numBlocks; i++) {
        PcodeBlockBasic* b = bg->getBlock(i);
        assert(b != nullptr && "Block pointer must not be null");
        PcodeOpAST* first = b->getFirstOp();
        PcodeOpAST* last = b->getLastOp();
        assert(first != nullptr && "Block must have first op (no truncation)");
        assert(last != nullptr && "Block must have last op (no early return)");
        printf("  Block %d: first=0x%llx last=0x%llx oc=%d out=%d in=%d\n",
               i,
               (unsigned long long)first->getSeqnum().getTarget().getOffset(),
               (unsigned long long)last->getSeqnum().getTarget().getOffset(),
               last->getOpcode(),
               b->getOutSize(), b->getInSize());
    }

    // Block 0 (BRANCH at 0x1000): 1 out edge → Block 2
    assert(bg->getBlock(0)->getOutSize() == 1 && "B0 must have 1 out edge");
    assert(bg->getBlock(0)->getOut(0) == bg->getBlock(2) && "B0 target must be B2");
    printf("[PASS] Block 0 → Block 2\n");

    // Block 1 (BRANCH at 0x1001): 1 out edge → Block 2
    assert(bg->getBlock(1)->getOutSize() == 1 && "B1 must have 1 out edge");
    assert(bg->getBlock(1)->getOut(0) == bg->getBlock(2) && "B1 target must be B2");
    printf("[PASS] Block 1 → Block 2\n");

    // Block 2 (COPY at 0x1002+0x1003, merge+exit): 0 out edges (last block)
    assert(bg->getBlock(2)->getOutSize() == 0 && "B2 exit must have 0 out edges");
    assert(bg->getBlock(2)->getInSize() == 2 && "B2 must have 2 in edges (B0+B1)");
    assert(bg->getBlock(2)->getIn(0) != nullptr && "B2 in[0] valid");
    assert(bg->getBlock(2)->getIn(1) != nullptr && "B2 in[1] valid");
    printf("[PASS] Block 2 merge point: 2 predecessors, 0 successors\n");

    // Verify entry node
    assert(bg->getStartNode() == 0 && "Entry must be block 0");
    printf("[PASS] Entry node is block 0\n");

    // --- Edge integrity: no dangling pointers ---
    int edgeCount = 0;
    for (int i = 0; i < numBlocks; i++) {
        PcodeBlockBasic* b = bg->getBlock(i);
        for (int j = 0; j < b->getOutSize(); j++) {
            assert(b->getOut(j) != nullptr && "Edge target must not be null");
            edgeCount++;
        }
    }
    printf("[PASS] All %d edge links valid (no dangling pointers)\n", edgeCount);

    // --- Verify no block has zero ops (no empty blocks from truncation) ---
    for (int i = 0; i < numBlocks; i++) {
        PcodeBlockBasic* b = bg->getBlock(i);
        assert(b->getFirstOp() != nullptr && "No empty blocks allowed");
        assert(b->getLastOp() != nullptr && "No empty blocks allowed");
    }
    printf("[PASS] All blocks are non-empty (no truncation)\n");

    // ====== Dominator Analysis Verification ======
    bg->computeDominators();

    // Graph topology: B0→B2, B1→B2. Entry is B0.
    // B1 is NOT reachable from entry B0 (no edge from B0→B1).
    // So B1 is unreachable and has no dominator.
    // B0 strictly dominates B2 (every path from entry to B2 goes through B0).
    assert(bg->getDominator(0) == -1 && "Entry B0 must have no dominator");
    assert(bg->getDominator(1) == -1 && "B1 unreachable: no dominator");
    assert(bg->getDominator(2) == 0 && "B2 must be dominated by entry B0");
    printf("[PASS] Dominators: idom[B0]=none idom[B1]=none(unreach) idom[B2]=B0\n");

    // Dominator tree children of B0 = {B2} only (B1 is unreachable)
    const auto& b0children = bg->getDominatorTreeChildren(0);
    assert(b0children.size() == 1 && "B0 has 1 child in dom tree (B2)");
    assert(b0children[0] == 2 && "B0 child must be B2");
    printf("[PASS] Dominator tree: B0→B2, B1 is unreachable\n");

    // Dominance frontiers
    const auto& df0 = bg->getDominanceFrontier(0);
    const auto& df1 = bg->getDominanceFrontier(1);
    const auto& df2 = bg->getDominanceFrontier(2);
    // DF(B0) = ∅ (B0 strictly dominates B2)
    // DF(B1) = {2} (B1→B2 but B1 does not strictly dominate B2)
    // DF(B2) = ∅ (leaf, exit)
    assert(df0.size() == 0 && "DF(B0) = ∅");
    assert(df1.size() == 1 && "DF(B1) = {B2}");
    assert(df1.find(2) != df1.end() && "DF(B1) must contain B2");
    assert(df2.size() == 0 && "DF(B2) = ∅");
    printf("[PASS] Dominance frontiers: DF(B0)=∅ DF(B1)={B2} DF(B2)=∅\n");

    // ====== Post-Dominator Verification ======
    bg->computePostDominators();

    // In this graph, B2 is the only exit block (0 outgoing edges).
    // Post-dominator relationship: a node p-post-dominates q if every path from q to
    // exit goes through p.
    //
    // B2 post-dominates all blocks: every path from any block to the exit (B2) must go
    // through B2 (trivial since B2 IS the exit).
    // B0 post-dominates only B0: from B0 you can reach B2 without going through B0 again.
    // B1 post-dominates only B1: same logic.
    //
    // So: ipostdom[B2] = none (exit), ipostdom[B0] = B2, ipostdom[B1] = B2
    assert(bg->getPostDominator(0) == 2 && "B0 must be post-dominated by exit B2");
    assert(bg->getPostDominator(1) == 2 && "B1 must be post-dominated by exit B2");
    assert(bg->getPostDominator(2) == -1 && "Exit B2 must have no post-dominator");
    printf("[PASS] Post-dominators: ipostdom[B0]=B2 ipostdom[B1]=B2 ipostdom[B2]=none\n");

    // ====== Final summary ======
    printf("\n=== VERIFICATION COMPLETE ===\n");
    printf("Blocks:    %d\n", numBlocks);
    printf("Edges:     %d\n", numEdges);
    printf("Entry:     %d\n", bg->getStartNode());
    printf("All assertions passed — no early returns, no truncation.\n");
    printf("\nCFG_LIVE_VERIFY: PASS\n");

    return 0;
}
