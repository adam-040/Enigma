#include <ghidra/FlowInfo.h>
#include <ghidra/FuncCallSpecs.h>
#include <ghidra/PcodeOp.h>
#include <ghidra/PcodeOpAST.h>
#include <ghidra/PcodeBlockBasic.h>
#include <ghidra/Types.h>
#include <ghidra/Varnode.h>
#include <stdexcept>
#include <map>
#include <set>
#include <algorithm>

namespace ghidra {

FlowInfo::FlowInfo(Funcdata& d, BlockGraph& b, std::vector<FuncCallSpecs*>& q)
    : data(d), bblocks(b), callList(q), insnCount(0), insnMax(100000),
      flowOverridePresent(false), flags(IGNORE_OUTOFBOUNDS | IGNORE_UNIMPLEMENTED) {
    baddr = data.getEntryPoint();
    eaddr = data.getEntryPoint().add(0x100000);
    minaddr = data.getEntryPoint();
    maxaddr = data.getEntryPoint();
}

FlowInfo::FlowInfo(Funcdata& d, BlockGraph& b, std::vector<FuncCallSpecs*>& q, const FlowInfo& op2)
    : data(d), bblocks(b), callList(q), insnCount(0), insnMax(op2.insnMax),
      baddr(op2.baddr), eaddr(op2.eaddr), minaddr(op2.minaddr), maxaddr(op2.maxaddr),
      flowOverridePresent(op2.flowOverridePresent), flags(op2.flags) {
}

bool FlowInfo::processInstruction(const Address& curAddr, bool& startBasic) {
    if (visited.find(curAddr) != visited.end()) {
        return false;
    }

    VisitStat vs;
    vs.seqAddr = curAddr;
    vs.time = insnCount;
    vs.size = 1;
    visited[curAddr] = vs;
    startBasic = true;

    if (curAddr.getOffset() < minaddr.getOffset()) {
        minaddr = curAddr;
    }
    Address endAddr = curAddr.add(vs.size);
    if (endAddr.getOffset() > maxaddr.getOffset()) {
        maxaddr = endAddr;
    }

    insnCount++;
    return true;
}

void FlowInfo::fallthru() {
    while (!addrList.empty()) {
        Address curAddr = addrList.back();
        addrList.pop_back();

        if (visited.find(curAddr) != visited.end()) {
            continue;
        }

        if (curAddr.getOffset() < baddr.getOffset() || curAddr.getOffset() >= eaddr.getOffset()) {
            flags |= OUTOFBOUNDS_PRESENT;
            if (flags & ERROR_OUTOFBOUNDS) {
                throw std::runtime_error("Flow out of bounds");
            }
            continue;
        }

        bool startBasic = false;
        processInstruction(curAddr, startBasic);

        if (insnCount > insnMax) {
            flags |= TOOMANYINSTRUCTIONS_PRESENT;
            if (flags & ERROR_TOOMANYINSTRUCTIONS) {
                throw std::runtime_error("Too many instructions");
            }
            break;
        }

        Address fallAddr = curAddr.add(1);
        if (fallAddr.getOffset() >= baddr.getOffset() && fallAddr.getOffset() < eaddr.getOffset()) {
            if (visited.find(fallAddr) == visited.end()) {
                addrList.push_back(fallAddr);
            }
        }
    }
}

// ----------------------------------------------------------------
// splitBasic: Scan all pcode ops across all current blocks,
// identify terminal ops (BRANCH, CBRANCH, etc.), and split into
// proper basic blocks. Each terminal op ends a block.
// ----------------------------------------------------------------
void FlowInfo::splitBasic() {
    // Collect all existing ops from all current blocks
    std::vector<PcodeOpAST*> allOps;
    for (int i = 0; i < bblocks.getNumBlocks(); i++) {
        PcodeBlockBasic* block = bblocks.getBlock(i);
        if (!block) continue;
        for (auto it = block->begin(); it != block->end(); ++it) {
            if (*it) allOps.push_back(*it);
        }
    }

    if (allOps.empty()) {
        bblocks.addBlock();
        return;
    }

    // Sort by sequence number to guarantee correct order
    std::stable_sort(allOps.begin(), allOps.end(),
        [](PcodeOpAST* a, PcodeOpAST* b) {
            return a->getSeqnum() < b->getSeqnum();
        });

    // Identify split indices: the position *after* each terminal op
    std::vector<size_t> splits;
    for (size_t i = 0; i < allOps.size(); i++) {
        int oc = allOps[i]->getOpcode();
        bool terminal = (oc == PcodeOp::BRANCH || oc == PcodeOp::CBRANCH ||
                          oc == PcodeOp::BRANCHIND || oc == PcodeOp::CALL ||
                          oc == PcodeOp::CALLIND || oc == PcodeOp::RETURN ||
                          oc == PcodeOp::CALLOTHER);
        if (terminal && i + 1 < allOps.size()) {
            splits.push_back(i + 1);
        }
    }

    // Clear existing blocks
    bblocks.clear();

    // Distribute ops into new blocks
    size_t start = 0;
    for (size_t split : splits) {
        PcodeBlockBasic* block = bblocks.addBlock();
        for (size_t i = start; i < split; i++) {
            block->insertEnd(allOps[i]);
        }
        block->rebuildCoverFromOps();
        start = split;
    }

    // Final block (remaining ops after last split)
    if (start < allOps.size()) {
        PcodeBlockBasic* block = bblocks.addBlock();
        for (size_t i = start; i < allOps.size(); i++) {
            block->insertEnd(allOps[i]);
        }
        block->rebuildCoverFromOps();
    }

    bblocks.setStartNode(0);
}

// ----------------------------------------------------------------
// collectEdges: Walk each block, examine its last pcode op, and
// create CFG edges (branch targets, fallthroughs, call/return).
// ----------------------------------------------------------------
void FlowInfo::collectEdges() {
    int numBlocks = bblocks.getNumBlocks();
    if (numBlocks == 0) return;

    // Build a map from instruction address to block index for target resolution
    std::map<uint64_t, int> addrToBlock;
    for (int i = 0; i < numBlocks; i++) {
        PcodeBlockBasic* block = bblocks.getBlock(i);
        PcodeOpAST* firstOp = block->getFirstOp();
        if (firstOp) {
            uint64_t addr = firstOp->getSeqnum().getTarget().getOffset();
            if (addrToBlock.find(addr) == addrToBlock.end()) {
                addrToBlock[addr] = i;
            }
        }
    }

    // Build a full cover lookup: for each address in each block
    std::map<uint64_t, int> fullAddrToBlock;
    for (int i = 0; i < numBlocks; i++) {
        PcodeBlockBasic* block = bblocks.getBlock(i);
        if (!block) continue;
        for (auto it = block->begin(); it != block->end(); ++it) {
            if (!(*it)) continue;
            uint64_t addr = (*it)->getSeqnum().getTarget().getOffset();
            fullAddrToBlock[addr] = i;
        }
    }

    // Shared: get the entry point's address space for target resolution
    const AddressSpace* space = data.getEntryPoint().getAddressSpace();

    for (int i = 0; i < numBlocks; i++) {
        PcodeBlockBasic* block = bblocks.getBlock(i);
        PcodeOpAST* lastOp = block->getLastOp();
        if (!lastOp) {
            // Empty block – edge to next sequential block if any
            if (i + 1 < numBlocks) {
                bblocks.addEdge(block, bblocks.getBlock(i + 1));
            }
            continue;
        }

        int oc = lastOp->getOpcode();

        if (oc == PcodeOp::BRANCH) {
            Varnode* targetVn = lastOp->getInput(0);
            if (targetVn && targetVn->isConstant()) {
                uint64_t tgtOff = static_cast<uint64_t>(targetVn->getOffset());
                auto it = fullAddrToBlock.find(tgtOff);
                if (it != fullAddrToBlock.end() && it->second >= 0 && it->second < numBlocks) {
                    bblocks.addEdge(block, bblocks.getBlock(it->second));
                }
            }
        }
        else if (oc == PcodeOp::CBRANCH) {
            // Conditional branch: edge to target AND fallthrough to next sequential block
            int targetBlock = -1;
            Varnode* targetVn = lastOp->getInput(0);
            if (targetVn && targetVn->isConstant()) {
                uint64_t tgtOff = targetVn->getOffset();
                auto it = fullAddrToBlock.find(tgtOff);
                if (it != fullAddrToBlock.end() && it->second >= 0 && it->second < numBlocks) {
                    targetBlock = it->second;
                    bblocks.addEdge(block, bblocks.getBlock(it->second));
                }
            }
            // Fallthrough to next block (skip if same as target)
            if (i + 1 < numBlocks && (i + 1) != targetBlock) {
                bblocks.addEdge(block, bblocks.getBlock(i + 1));
            }
        }
        else if (oc == PcodeOp::CALL || oc == PcodeOp::CALLIND) {
            // Call: edge to target (if resolvable) and fallthrough return edge
            int targetBlock = -1;
            Varnode* targetVn = lastOp->getInput(0);
            if (targetVn && targetVn->isConstant()) {
                uint64_t tgtOff = targetVn->getOffset();
                auto it = fullAddrToBlock.find(tgtOff);
                if (it != fullAddrToBlock.end() && it->second >= 0 && it->second < numBlocks) {
                    targetBlock = it->second;
                    bblocks.addEdge(block, bblocks.getBlock(it->second));
                }
            }
            // Call returns to the next sequential block (skip if same as target)
            if (i + 1 < numBlocks && (i + 1) != targetBlock) {
                bblocks.addEdge(block, bblocks.getBlock(i + 1));
            }
        }
        else if (oc == PcodeOp::BRANCHIND) {
            // Indirect branch — target unknown statically; no outgoing edges
        }
        else if (oc == PcodeOp::RETURN) {
            // Function return — no outgoing edges
        }
        else {
            // Non-terminal op: fallthrough to next sequential block
            if (i + 1 < numBlocks) {
                bblocks.addEdge(block, bblocks.getBlock(i + 1));
            }
        }
    }
}

// ----------------------------------------------------------------
// connectBasic: Post-processing — remove duplicate edges, ensure
// the CFG is well-formed.
// ----------------------------------------------------------------
void FlowInfo::connectBasic() {
    int numBlocks = bblocks.getNumBlocks();
    if (numBlocks == 0) return;

    // Remove duplicate edges from each block's outgoing list
    for (int i = 0; i < numBlocks; i++) {
        PcodeBlockBasic* block = bblocks.getBlock(i);

        // Use a set to detect duplicate destinations
        std::set<PcodeBlockBasic*> seen;
        const auto& outEdges = block->getOutEdges();
        for (auto* edge : outEdges) {
            if (edge && edge->dest) {
                if (!seen.insert(edge->dest).second) {
                    // Already have an edge to this destination — mark for removal
                    // (we keep the first occurrence)
                    edge->dest = nullptr; // signals removal
                }
            }
        }
    }

    // Ensure startnode points to entry block
    bblocks.setStartNode(0);
}

void FlowInfo::handleOutOfBounds(const Address& from, const Address& to) {
    flags |= OUTOFBOUNDS_PRESENT;
}

void FlowInfo::newAddress(PcodeOpAST* from, const Address& to) {
    if (visited.find(to) == visited.end()) {
        addrList.push_back(to);
    }
}

// ----------------------------------------------------------------
// generateOps: Build the visited-address map from the pcode ops
// already placed in Funcdata by Sleigh. Does NOT create synthetic
// ops — uses the real ops from the disassembly.
// ----------------------------------------------------------------
void FlowInfo::generateOps() {
    addrList.clear();
    visited.clear();
    insnCount = 0;
    minaddr = data.getEntryPoint();
    maxaddr = data.getEntryPoint();

    // Enumerate all real pcode ops in the Funcdata
    for (int i = 0; i < data.getNumOps(); i++) {
        PcodeOpAST* op = data.getOp(i);
        if (!op) continue;

        Address opAddr = op->getSeqnum().getTarget();

        // Only record each instruction address once
        if (visited.find(opAddr) == visited.end()) {
            VisitStat vs;
            vs.seqAddr = opAddr;
            vs.time = insnCount;
            vs.size = 1;
            visited[opAddr] = vs;

            if (opAddr.getOffset() < minaddr.getOffset()) {
                minaddr = opAddr;
            }
            Address endAddr = opAddr.add(1);
            if (endAddr.getOffset() > maxaddr.getOffset()) {
                maxaddr = endAddr;
            }
            insnCount++;
        }
    }

    // If no ops were found, fall back to entry-point-based discovery
    // to maintain backward compatibility
    if (insnCount == 0) {
        addrList.push_back(data.getEntryPoint());
        fallthru();
    }
}

void FlowInfo::generateBlocks() {
    splitBasic();
    collectEdges();
    connectBasic();
}

} // namespace ghidra
