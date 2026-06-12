#include <ghidra/Heritage.h>
#include <ghidra/Funcdata.h>
#include <ghidra/BlockGraph.h>
#include <ghidra/VarnodeAST.h>
#include <ghidra/PcodeOpAST.h>
#include <ghidra/PcodeBlockBasic.h>
#include <ghidra/OpCode.h>
#include <algorithm>
#include <set>
#include <map>

namespace ghidra {

// --- VariableStack helpers ---

void Heritage::pushVersion(int16_t mergeGroup, int16_t v) {
    varStack[mergeGroup].push_back(v);
}

int16_t Heritage::popVersion(int16_t mergeGroup) {
    auto it = varStack.find(mergeGroup);
    if (it != varStack.end() && !it->second.empty()) {
        int16_t v = it->second.back();
        it->second.pop_back();
        if (it->second.empty()) {
            varStack.erase(it);
        }
        return v;
    }
    return -1;
}

int16_t Heritage::currentVersion(int16_t mergeGroup) const {
    auto it = varStack.find(mergeGroup);
    if (it != varStack.end() && !it->second.empty()) {
        return it->second.back();
    }
    return -1;
}

// --- Heritage core ---

Heritage::Heritage(Funcdata* f)
    : fd(f), nextMergeGroup(0), nextVersion(0), ssaBuilt(false) {
}

void Heritage::initialize() {
    records.clear();
    nextMergeGroup = 0;
    nextVersion = 0;
    varStack.clear();
    ssaBuilt = false;

    for (int i = 0; i < fd->getNumVarnodes(); i++) {
        VarnodeAST* vn = fd->getVarnode(i);
        if (!vn) continue;

        HeritageRecord rec;
        rec.varnode = vn;
        rec.mergeGroup = -1;
        rec.isInput = vn->isInput();
        rec.isPersist = vn->isPersistent();
        records.push_back(rec);
    }
}

void Heritage::execute() {
    // Step 1: Assign initial merge groups (varnodes sharing same address & size)
    for (auto& rec : records) {
        if (rec.mergeGroup < 0) {
            rec.mergeGroup = static_cast<int4>(nextMergeGroup);
            nextMergeGroup++;
        }

        buildCover(rec.varnode);

        // Propagate merge group through def-use chain
        PcodeOp* def = rec.varnode->getDef();
        if (def) {
            for (int i = 0; i < def->getNumInputs(); i++) {
                Varnode* inputVn = def->getInput(i);
                if (!inputVn) continue;
                VarnodeAST* inputAst = static_cast<VarnodeAST*>(inputVn);
                for (auto& otherRec : records) {
                    if (otherRec.varnode == inputAst && otherRec.mergeGroup < 0) {
                        otherRec.mergeGroup = rec.mergeGroup;
                    }
                }
            }
        }
    }

    // Step 2: Insert phi nodes (MULTIEQUAL ops) at dominance frontiers
    const BlockGraph* bg = fd->getBlockGraph();
    if (!bg || bg->getNumBlocks() == 0) {
        ssaBuilt = true;
        fd->setSSA(true);
        return;
    }

    // Group varnodes by merge group for phi insertion
    std::map<int4, std::vector<VarnodeAST*>> groupMap;
    for (auto& rec : records) {
        groupMap[rec.mergeGroup].push_back(rec.varnode);
    }

    // Insert phis for each group
    for (const auto& gEntry : groupMap) {
        int4 groupId = gEntry.first;
        const auto& groupVns = gEntry.second;
        insertPielementsForGroup(groupId, groupVns, *bg);
    }

    // Step 3: Rename variables via dominator tree walk
    varStack.clear();
    nextVersion = 0;
    int startNode = bg->getStartNode();
    if (startNode >= 0 && startNode < bg->getNumBlocks()) {
        renameBlock(bg->getBlock(startNode), *bg);
    }

    ssaBuilt = true;
    fd->setSSA(true);
}

// --- Phi insertion ---

void Heritage::collectDefiningBlocks(int4 groupId, std::set<int>& defBlocks) const {
    for (const auto& rec : records) {
        if (rec.mergeGroup != groupId) continue;
        VarnodeAST* vn = rec.varnode;
        if (!vn) continue;
        if (vn->isInput()) continue; // inputs don't have definitions
        PcodeOp* def = vn->getDef();
        if (!def) continue;
        PcodeOpAST* defAst = dynamic_cast<PcodeOpAST*>(def);
        if (!defAst) continue;
        PcodeBlockBasic* parent = defAst->getParent();
        if (!parent) continue;
        const BlockGraph* bg = fd->getBlockGraph();
        if (!bg) continue;
        for (int bi = 0; bi < bg->getNumBlocks(); bi++) {
            if (bg->getBlock(bi) == parent) {
                defBlocks.insert(bi);
                break;
            }
        }
    }
}

void Heritage::insertPielementsForGroup(int4 groupId,
    const std::vector<VarnodeAST*>& groupVns, const BlockGraph& bg) {

    // Collect all blocks that define varnodes in this group
    std::set<int> defBlocks;
    for (VarnodeAST* vn : groupVns) {
        if (!vn || vn->isInput()) continue;
        PcodeOp* def = vn->getDef();
        if (!def) continue;
        PcodeOpAST* defAst = dynamic_cast<PcodeOpAST*>(def);
        if (!defAst) continue;
        PcodeBlockBasic* parent = defAst->getParent();
        if (!parent) continue;
        for (int bi = 0; bi < bg.getNumBlocks(); bi++) {
            if (bg.getBlock(bi) == parent) {
                defBlocks.insert(bi);
                break;
            }
        }
    }

    // If no defining blocks, skip this group
    if (defBlocks.empty()) return;

    // Compute the iterated dominance frontier (IDF) for this group
    // Start with the dominance frontier of each defining block
    std::set<int> workSet;
    std::set<int> inserted;
    for (int b : defBlocks) {
        const std::set<int>& df = bg.getDominanceFrontier(b);
        for (int f : df) {
            workSet.insert(f);
        }
    }

    // Iteratively add dominance frontiers of frontier blocks
    while (!workSet.empty()) {
        int b = *workSet.begin();
        workSet.erase(workSet.begin());

        // Check if already inserted for this block+group
        if (inserted.find(b) != inserted.end()) continue;
        inserted.insert(b);

        // Create MULTIEQUAL op at head of block b
        PcodeBlockBasic* block = bg.getBlock(b);
        if (!block) continue;

        // Determine size from first group varnode
        int vnSize = 4;
        if (!groupVns.empty() && groupVns[0]) {
            vnSize = groupVns[0]->getSize();
        }

        // Create a new varnode for the phi output
        Address phiAddr = block->getStart();
        VarnodeAST* phiVn = fd->createVarnode(phiAddr, static_cast<uint4>(vnSize),
            static_cast<int32_t>(fd->getNumVarnodes() + groupId * 1000 + b));
        phiVn->setMergeGroup(static_cast<int16_t>(groupId));

        // Create MULTIEQUAL op with one input per predecessor
        int numPreds = block->getInSize();
        PcodeOpAST* phiOp = fd->createOp(phiAddr, static_cast<int>(OpCode::CPUI_MULTIEQUAL), numPreds);
        phiOp->setOutput(phiVn);
        phiVn->setDef(phiOp);

        // Insert at head of block
        block->insertBefore(block->begin(), phiOp);
        phiOp->setParent(block);

        // Add to Heritage records
        HeritageRecord phiRec;
        phiRec.varnode = phiVn;
        phiRec.mergeGroup = static_cast<int4>(groupId);
        phiRec.isInput = false;
        phiRec.isPersist = false;
        records.push_back(phiRec);

        // The phi's defining block also needs IDF iteration
        const std::set<int>& bDf = bg.getDominanceFrontier(b);
        for (int f : bDf) {
            if (inserted.find(f) == inserted.end()) {
                workSet.insert(f);
            }
        }
    }
}

// --- Variable renaming ---

void Heritage::renameBlock(PcodeBlockBasic* block, const BlockGraph& bg) {
    if (!block) return;

    // Track which groups we pushed versions for in this block
    std::vector<int16_t> pushedGroups;

    // Phase 1: Rename phi (MULTIEQUAL) outputs and inputs
    for (auto it = block->begin(); it != block->end(); ++it) {
        PcodeOpAST* op = *it;
        if (!op) continue;
        if (op->getOpcode() != static_cast<int>(OpCode::CPUI_MULTIEQUAL)) break;

        // Rename phi output
        Varnode* outVn = op->getOutput();
        if (!outVn) continue;
        VarnodeAST* outAst = static_cast<VarnodeAST*>(outVn);
        int16_t mg = static_cast<int16_t>(outAst->getMergeGroup());
        int16_t ver = nextVersion++;
        outAst->setVersion(ver);
        pushVersion(mg, ver);
        pushedGroups.push_back(mg);

        // Rename each phi input: for predecessor i, use current version
        // in the predecessor block (which has already been renamed if we
        // visit in dominator tree pre-order)
        for (int i = 0; i < op->getNumInputs(); i++) {
            PcodeBlockBasic* pred = block->getIn(i);
            if (pred) {
                // Find the current version of this merge group at end of predecessor
                // This is the version after predecessor was renamed
                // We use the current stack top, which should be the version
                // available at the end of the predecessor
                int16_t predVer = currentVersion(mg);
                if (predVer >= 0) {
                    // The phi input is implicitly the current version
                    // We need to create or reuse a varnode for this input
                    // For now, set the input to the current top-of-stack varnode
                    // Search for a varnode with this merge group and version
                    for (auto& rec : records) {
                        if (rec.mergeGroup == static_cast<int4>(mg) &&
                            rec.varnode && rec.varnode->getVersion() == predVer) {
                            op->setInput(rec.varnode, i);
                            break;
                        }
                    }
                }
            }
        }
    }

    // Phase 2: Rename non-phi ops
    for (auto it = block->begin(); it != block->end(); ++it) {
        PcodeOpAST* op = *it;
        if (!op) continue;
        if (op->getOpcode() == static_cast<int>(OpCode::CPUI_MULTIEQUAL)) continue;

        // Rename inputs: replace with current version of their merge group
        for (int i = 0; i < op->getNumInputs(); i++) {
            Varnode* inVn = op->getInput(i);
            if (!inVn) continue;
            VarnodeAST* inAst = static_cast<VarnodeAST*>(inVn);
            int16_t mg = static_cast<int16_t>(inAst->getMergeGroup());
            if (mg < 0) continue;

            int16_t curVer = currentVersion(mg);
            if (curVer >= 0 && curVer != inAst->getVersion()) {
                // Find the varnode with the current version in this merge group
                for (auto& rec : records) {
                    if (rec.mergeGroup == static_cast<int4>(mg) &&
                        rec.varnode && rec.varnode->getVersion() == curVer &&
                        rec.varnode != inAst) {
                        // Rewire: replace old vn with new vn as input
                        inAst->removeDescendant(op);
                        op->setInput(rec.varnode, i);
                        rec.varnode->addDescendant(op);
                        break;
                    }
                }
            }
        }

        // Rename output: assign new version
        Varnode* outVn = op->getOutput();
        if (!outVn) continue;
        VarnodeAST* outAst = static_cast<VarnodeAST*>(outVn);
        int16_t mg = static_cast<int16_t>(outAst->getMergeGroup());
        if (mg < 0) continue;

        int16_t ver = nextVersion++;
        outAst->setVersion(ver);
        pushVersion(mg, ver);
        pushedGroups.push_back(mg);
    }

    // Phase 3: Recurse into dominator tree children
    // Find this block's index
    int blockIndex = -1;
    for (int bi = 0; bi < bg.getNumBlocks(); bi++) {
        if (bg.getBlock(bi) == block) {
            blockIndex = bi;
            break;
        }
    }

    if (blockIndex >= 0) {
        const std::vector<int>& children = bg.getDominatorTreeChildren(blockIndex);
        for (int childIdx : children) {
            PcodeBlockBasic* childBlock = bg.getBlock(childIdx);
            if (childBlock) {
                renameBlock(childBlock, bg);
            }
        }
    }

    // Phase 4: Pop versions pushed in this block
    for (auto it = pushedGroups.rbegin(); it != pushedGroups.rend(); ++it) {
        popVersion(*it);
    }
}

// --- Existing Heritage API ---

const Heritage::HeritageRecord* Heritage::getRecord(int4 index) const {
    if (index >= 0 && index < static_cast<int4>(records.size())) {
        return &records[index];
    }
    return nullptr;
}

Heritage::HeritageRecord* Heritage::getRecord(int4 index) {
    if (index >= 0 && index < static_cast<int4>(records.size())) {
        return &records[index];
    }
    return nullptr;
}

int4 Heritage::assignMergeGroup(VarnodeAST* vn) {
    for (auto& rec : records) {
        if (rec.varnode == vn) {
            if (rec.mergeGroup < 0) {
                rec.mergeGroup = nextMergeGroup++;
            }
            return rec.mergeGroup;
        }
    }
    return -1;
}

int4 Heritage::getMergeGroup(VarnodeAST* vn) const {
    for (const auto& rec : records) {
        if (rec.varnode == vn) {
            return rec.mergeGroup;
        }
    }
    return -1;
}

void Heritage::markInput(VarnodeAST* vn) {
    for (auto& rec : records) {
        if (rec.varnode == vn) {
            rec.isInput = true;
            return;
        }
    }
}

void Heritage::markPersist(VarnodeAST* vn) {
    for (auto& rec : records) {
        if (rec.varnode == vn) {
            rec.isPersist = true;
            return;
        }
    }
}

bool Heritage::isInput(VarnodeAST* vn) const {
    for (const auto& rec : records) {
        if (rec.varnode == vn) {
            return rec.isInput;
        }
    }
    return false;
}

bool Heritage::isPersist(VarnodeAST* vn) const {
    for (const auto& rec : records) {
        if (rec.varnode == vn) {
            return rec.isPersist;
        }
    }
    return false;
}

void Heritage::buildCover(VarnodeAST* vn) {
    for (auto& rec : records) {
        if (rec.varnode == vn) {
            rec.cover.clear();
            Address addr = vn->getAddress();
            rec.cover.addRange(addr, addr);
            return;
        }
    }
}

const Cover* Heritage::getCover(VarnodeAST* vn) const {
    for (const auto& rec : records) {
        if (rec.varnode == vn) {
            return &rec.cover;
        }
    }
    return nullptr;
}

void Heritage::clear() {
    records.clear();
    nextMergeGroup = 0;
    nextVersion = 0;
    varStack.clear();
    ssaBuilt = false;
}

// --- Merge (unchanged) ---

Merge::Merge(Funcdata* f) : fd(f), nextGroupId(0) {
}

void Merge::initialize() {
    groups.clear();
    nextGroupId = 0;
}

void Merge::execute() {
    for (int i = 0; i < fd->getNumVarnodes(); i++) {
        VarnodeAST* vn = fd->getVarnode(i);
        if (!vn) continue;

        int4 groupId = -1;
        for (int g = 0; g < static_cast<int4>(groups.size()); g++) {
            for (auto* groupVn : groups[g].varnodes) {
                if (groupVn->getUniqueId() == vn->getUniqueId()) {
                    groupId = g;
                    break;
                }
            }
            if (groupId >= 0) break;
        }

        if (groupId < 0) {
            groupId = createGroup();
        }

        addVarnodeToGroup(groupId, vn);
    }
}

const Merge::MergeGroup* Merge::getGroup(int4 index) const {
    if (index >= 0 && index < static_cast<int4>(groups.size())) {
        return &groups[index];
    }
    return nullptr;
}

Merge::MergeGroup* Merge::getGroup(int4 index) {
    if (index >= 0 && index < static_cast<int4>(groups.size())) {
        return &groups[index];
    }
    return nullptr;
}

int4 Merge::createGroup() {
    MergeGroup group;
    group.id = nextGroupId++;
    group.isInput = false;
    group.isPersist = false;
    groups.push_back(group);
    return group.id;
}

void Merge::addVarnodeToGroup(int4 groupId, VarnodeAST* vn) {
    if (groupId < 0 || groupId >= static_cast<int4>(groups.size())) return;

    for (auto* existingVn : groups[groupId].varnodes) {
        if (existingVn == vn) return;
    }

    groups[groupId].varnodes.push_back(vn);
}

void Merge::mergeGroups(int4 groupId1, int4 groupId2) {
    if (groupId1 < 0 || groupId1 >= static_cast<int4>(groups.size())) return;
    if (groupId2 < 0 || groupId2 >= static_cast<int4>(groups.size())) return;
    if (groupId1 == groupId2) return;

    for (auto* vn : groups[groupId2].varnodes) {
        addVarnodeToGroup(groupId1, vn);
    }

    groups[groupId2].varnodes.clear();
}

int4 Merge::getGroupId(VarnodeAST* vn) const {
    for (int g = 0; g < static_cast<int4>(groups.size()); g++) {
        for (auto* groupVn : groups[g].varnodes) {
            if (groupVn == vn) {
                return g;
            }
        }
    }
    return -1;
}

VarnodeAST* Merge::getGroupVarnode(int4 groupId, int4 index) const {
    if (groupId < 0 || groupId >= static_cast<int4>(groups.size())) return nullptr;
    if (index < 0 || index >= static_cast<int4>(groups[groupId].varnodes.size())) return nullptr;
    return groups[groupId].varnodes[index];
}

int4 Merge::getGroupSize(int4 groupId) const {
    if (groupId < 0 || groupId >= static_cast<int4>(groups.size())) return 0;
    return static_cast<int4>(groups[groupId].varnodes.size());
}

void Merge::markGroupInput(int4 groupId) {
    if (groupId < 0 || groupId >= static_cast<int4>(groups.size())) return;
    groups[groupId].isInput = true;
}

void Merge::markGroupPersist(int4 groupId) {
    if (groupId < 0 || groupId >= static_cast<int4>(groups.size())) return;
    groups[groupId].isPersist = true;
}

bool Merge::isGroupInput(int4 groupId) const {
    if (groupId < 0 || groupId >= static_cast<int4>(groups.size())) return false;
    return groups[groupId].isInput;
}

bool Merge::isGroupPersist(int4 groupId) const {
    if (groupId < 0 || groupId >= static_cast<int4>(groups.size())) return false;
    return groups[groupId].isPersist;
}

void Merge::buildGroupCover(int4 groupId) {
    if (groupId < 0 || groupId >= static_cast<int4>(groups.size())) return;

    groups[groupId].cover.clear();
    for (auto* vn : groups[groupId].varnodes) {
        Address addr = vn->getAddress();
        groups[groupId].cover.addRange(addr, addr);
    }
}

const Cover* Merge::getGroupCover(int4 groupId) const {
    if (groupId < 0 || groupId >= static_cast<int4>(groups.size())) return nullptr;
    return &groups[groupId].cover;
}

void Merge::clear() {
    groups.clear();
    nextGroupId = 0;
}

} // namespace ghidra
