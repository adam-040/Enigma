#include <ghidra/ActionManager.h>
#include <ghidra/Funcdata.h>
#include <ghidra/PcodeOpAST.h>
#include <ghidra/VarnodeAST.h>
#include <ghidra/OpCode.h>
#include <ghidra/TypePropagation.h>
#include <ghidra/Architecture.h>
#include <iostream>

namespace ghidra {

ActionManager::ActionManager(Architecture* arch)
    : architecture(arch), totalIterations(0), maxTotalIterations(50), verbose(false) {
}

ActionManager::~ActionManager() {
    for (auto& pair : pipelines) {
        delete pair.second;
    }
}

void ActionManager::initialize() {
    pipelines[PIPELINE_PREPROCESS] = new ActionList("preprocess", Action::CATEGORY_ALL, 10);
    pipelines[PIPELINE_CONSTANT] = new ActionList("constant", Action::CATEGORY_CONSTANT, 20);
    pipelines[PIPELINE_COPYPROP] = new ActionList("copyprop", Action::CATEGORY_COPY, 20);
    pipelines[PIPELINE_DEADCODE] = new ActionList("deadcode", Action::CATEGORY_DEADCODE, 20);
    pipelines[PIPELINE_MERGE] = new ActionList("merge", Action::CATEGORY_MERGE, 20);
    pipelines[PIPELINE_TYPEPROP] = new ActionList("typeprop", Action::CATEGORY_TYPEPROP, 20);
    pipelines[PIPELINE_TRANSFORM] = new ActionList("transform", Action::CATEGORY_TRANSFORM, 20);
    pipelines[PIPELINE_POSTPROCESS] = new ActionList("postprocess", Action::CATEGORY_ALL, 10);

    pipelines[PIPELINE_CONSTANT]->addAction(new ActionConstantFold());
    pipelines[PIPELINE_COPYPROP]->addAction(new ActionCopyPropagate());
    pipelines[PIPELINE_DEADCODE]->addAction(new ActionDeadCodeElim());
    pipelines[PIPELINE_MERGE]->addAction(new ActionMergeVarnodes());
    pipelines[PIPELINE_TYPEPROP]->addAction(new ActionTypePropagate(architecture));
    pipelines[PIPELINE_TRANSFORM]->addAction(new ActionLandmark());
    pipelines[PIPELINE_TRANSFORM]->addAction(new ActionUnreachable());
    pipelines[PIPELINE_TRANSFORM]->addAction(new ActionSwitchRecovery());
    pipelines[PIPELINE_POSTPROCESS]->addAction(new ActionLandmark());
}

void ActionManager::execute(Funcdata& fd) {
    totalIterations = 0;

    for (int p = 0; p < PIPELINE_MAX; p++) {
        Pipeline pipeline = static_cast<Pipeline>(p);
        ActionList* list = getPipeline(pipeline);
        if (!list) continue;

        uint4 status = list->execute(fd);
        totalIterations++;

        if (verbose) {
            std::cout << "Pipeline " << p << " status: " << status << std::endl;
        }

        if (totalIterations >= maxTotalIterations) break;
    }

    ruleLibrary.applyAll(fd);
}

void ActionManager::executePipeline(Pipeline p, Funcdata& fd) {
    ActionList* list = getPipeline(p);
    if (list) {
        list->execute(fd);
        totalIterations++;
    }
}

ActionList* ActionManager::getPipeline(Pipeline p) const {
    auto it = pipelines.find(p);
    return (it != pipelines.end()) ? it->second : nullptr;
}

void ActionManager::setPipeline(Pipeline p, ActionList* list) {
    auto it = pipelines.find(p);
    if (it != pipelines.end()) {
        delete it->second;
    }
    pipelines[p] = list;
}

void ActionManager::enableAllRules() {
    ruleLibrary.enableAll();
}

void ActionManager::disableAllRules() {
    ruleLibrary.disableAll();
}

void ActionManager::enableRule(const std::string& name) {
    ruleLibrary.enableRule(name);
}

void ActionManager::disableRule(const std::string& name) {
    ruleLibrary.disableRule(name);
}

void ActionManager::resetCounts() {
    totalIterations = 0;
    for (auto& pair : pipelines) {
        for (int i = 0; i < pair.second->getNumActions(); i++) {
            pair.second->getAction(i)->resetCount();
        }
    }
    for (int i = 0; i < ruleLibrary.getNumRules(); i++) {
        ruleLibrary.getRule(i)->resetCount();
    }
}

static uint64_t foldConstants(PcodeOpAST* op) {
    uint64_t v0 = static_cast<uint64_t>(op->getInput(0)->getOffset());
    if (op->getNumInputs() == 1) {
        switch (static_cast<OpCode>(op->getOpcode())) {
            case OpCode::CPUI_INT_NEGATE: return ~v0;
            case OpCode::CPUI_INT_2COMP:  return ~v0 + 1;
            case OpCode::CPUI_BOOL_NEGATE: return v0 ? 0 : 1;
            case OpCode::CPUI_COPY:       return v0;
            default: return v0;
        }
    }
    uint64_t v1 = static_cast<uint64_t>(op->getInput(1)->getOffset());
    switch (static_cast<OpCode>(op->getOpcode())) {
        case OpCode::CPUI_INT_ADD:    return v0 + v1;
        case OpCode::CPUI_INT_SUB:    return v0 - v1;
        case OpCode::CPUI_INT_MULT:   return v0 * v1;
        case OpCode::CPUI_INT_DIV:    return v1 ? v0 / v1 : 0;
        case OpCode::CPUI_INT_SDIV:   return v1 ? static_cast<uint64_t>(static_cast<int64_t>(v0) / static_cast<int64_t>(v1)) : 0;
        case OpCode::CPUI_INT_REM:    return v1 ? v0 % v1 : 0;
        case OpCode::CPUI_INT_SREM:   return v1 ? static_cast<uint64_t>(static_cast<int64_t>(v0) % static_cast<int64_t>(v1)) : 0;
        case OpCode::CPUI_INT_AND:    return v0 & v1;
        case OpCode::CPUI_INT_OR:     return v0 | v1;
        case OpCode::CPUI_INT_XOR:    return v0 ^ v1;
        case OpCode::CPUI_INT_LEFT:   return v0 << (v1 & 0x3f);
        case OpCode::CPUI_INT_RIGHT:  return v0 >> (v1 & 0x3f);
        case OpCode::CPUI_INT_SRIGHT: return static_cast<uint64_t>(static_cast<int64_t>(v0) >> (v1 & 0x3f));
        case OpCode::CPUI_INT_EQUAL:  return v0 == v1 ? 1 : 0;
        case OpCode::CPUI_INT_NOTEQUAL: return v0 != v1 ? 1 : 0;
        case OpCode::CPUI_INT_LESS:   return v0 < v1 ? 1 : 0;
        case OpCode::CPUI_INT_LESSEQUAL: return v0 <= v1 ? 1 : 0;
        case OpCode::CPUI_INT_SLESS:  return static_cast<int64_t>(v0) < static_cast<int64_t>(v1) ? 1 : 0;
        case OpCode::CPUI_INT_SLESSEQUAL: return static_cast<int64_t>(v0) <= static_cast<int64_t>(v1) ? 1 : 0;
        default: return 0;
    }
}

ActionConstantFold::ActionConstantFold()
    : Action("constant_fold", Action::CATEGORY_CONSTANT, "Fold constant operations") {
}

uint4 ActionConstantFold::apply(Funcdata& fd) {
    uint4 status = Action::STATUS_NONE;

    for (int i = fd.getNumOps() - 1; i >= 0; i--) {
        PcodeOpAST* op = fd.getOp(i);
        if (!op || op->isDead()) continue;
        if (!op->getOutput()) continue;

        int opc = op->getOpcode();
        if (opc == CPUI_COPY || opc == CPUI_MULTIEQUAL || opc == CPUI_INDIRECT ||
            opc == CPUI_LOAD || opc == CPUI_STORE || opc == CPUI_BRANCH ||
            opc == CPUI_CBRANCH || opc == CPUI_BRANCHIND || opc == CPUI_CALL ||
            opc == CPUI_CALLIND || opc == CPUI_CALLOTHER || opc == CPUI_RETURN) continue;

        bool allConst = true;
        for (int j = 0; j < op->getNumInputs(); j++) {
            Varnode* vn = op->getInput(j);
            if (!vn || !vn->isConstant()) { allConst = false; break; }
        }
        if (!allConst || op->getNumInputs() == 0) continue;

        uint64_t result = foldConstants(op);
        uint4 sz = op->getOutput()->getSize();
        if (sz == 0) sz = 1;

        VarnodeAST* constVn = fd.newConstant(result, sz);
        int ninputs = op->getNumInputs();
        for (int j = ninputs - 1; j > 0; j--) {
            op->removeInput(j);
        }
        op->setOpcode(CPUI_COPY);
        op->setInput(constVn, 0);
        constVn->addDescendant(op);
        applyCount++;
        status |= Action::STATUS_APPLIED;
    }

    if (applyCount == 0) status |= Action::STATUS_SKIPPED;
    return status;
}

ActionCopyPropagate::ActionCopyPropagate()
    : Action("copy_propagate", Action::CATEGORY_COPY, "Propagate constant copies") {
}

uint4 ActionCopyPropagate::apply(Funcdata& fd) {
    uint4 status = Action::STATUS_NONE;

    for (int i = fd.getNumOps() - 1; i >= 0; i--) {
        PcodeOpAST* op = fd.getOp(i);
        if (!op || op->isDead()) continue;
        if (static_cast<int>(op->getOpcode()) != static_cast<int>(OpCode::CPUI_COPY)) continue;

        VarnodeAST* input = static_cast<VarnodeAST*>(op->getInput(0));
        VarnodeAST* output = static_cast<VarnodeAST*>(op->getOutput());
        if (!input || !output) continue;
        if (output->hasNoDescend()) continue;

        // Only propagate constants (safe across SSA versions)
        if (!input->isConstant()) continue;

        fd.replaceVarnode(output, input);
        fd.removeOp(op);
        applyCount++;
        status |= Action::STATUS_APPLIED;
    }

    if (applyCount == 0) status |= Action::STATUS_SKIPPED;
    return status;
}

ActionDeadCodeElim::ActionDeadCodeElim()
    : Action("dead_code_elim", Action::CATEGORY_DEADCODE, "Eliminate dead code") {
}

uint4 ActionDeadCodeElim::apply(Funcdata& fd) {
    uint4 status = Action::STATUS_NONE;

    for (int i = fd.getNumOps() - 1; i >= 0; i--) {
        PcodeOpAST* op = fd.getOp(i);
        if (!op || op->isDead()) continue;

        int opc = op->getOpcode();
        if (opc == CPUI_CALL || opc == CPUI_CALLIND || opc == CPUI_CALLOTHER ||
            opc == CPUI_STORE || opc == CPUI_BRANCH || opc == CPUI_CBRANCH ||
            opc == CPUI_BRANCHIND || opc == CPUI_RETURN) continue;

        Varnode* output = op->getOutput();
        if (!output) continue;
        VarnodeAST* outputAst = static_cast<VarnodeAST*>(output);
        if (outputAst->hasNoDescend() && !outputAst->isPersistent() && !outputAst->isAddrTied()) {
            fd.removeOp(op);
            applyCount++;
            status |= Action::STATUS_APPLIED;
        }
    }

    if (applyCount == 0) status |= Action::STATUS_SKIPPED;
    return status;
}

ActionMergeVarnodes::ActionMergeVarnodes()
    : Action("merge_varnodes", Action::CATEGORY_MERGE, "Merge varnodes") {
}

uint4 ActionMergeVarnodes::apply(Funcdata& fd) {
    uint4 status = Action::STATUS_NONE;

    for (int i = fd.getNumOps() - 1; i >= 0; i--) {
        PcodeOpAST* op = fd.getOp(i);
        if (!op || op->isDead()) continue;

        VarnodeAST* output = static_cast<VarnodeAST*>(op->getOutput());
        if (!output || !output->isFree() || output->isPersistent() || output->isAddrTied()) continue;
        if (output->hasNoDescend()) continue;

        PcodeOp* loneDesc = output->getLoneDescend();
        if (loneDesc && op->getNumInputs() > 0) {
            VarnodeAST* input = static_cast<VarnodeAST*>(op->getInput(0));
            if (input && input != output) {
                fd.replaceVarnode(output, input);
                fd.removeOp(op);
                applyCount++;
                status |= Action::STATUS_APPLIED;
            }
        }
    }

    if (applyCount == 0) status |= Action::STATUS_SKIPPED;
    return status;
}

ActionTypePropagate::ActionTypePropagate(Architecture* arch)
    : Action("type_propagate", Action::CATEGORY_TYPEPROP, "Propagate types"), architecture(arch) {
}

uint4 ActionTypePropagate::apply(Funcdata& fd) {
    uint4 status = Action::STATUS_NONE;
    TypeFactory* factory = nullptr;
    if (architecture) {
        factory = &architecture->getTypeFactory();
    }

    TypePropagation engine(fd, factory);
    int4 count = engine.propagate();
    if (count > 0) {
        applyCount += count;
        status |= Action::STATUS_APPLIED;
    }

    if (applyCount == 0) status |= Action::STATUS_SKIPPED;
    return status;
}

ActionLandmark::ActionLandmark()
    : Action("landmark", Action::CATEGORY_TRANSFORM, "Identify block landmarks") {
}

uint4 ActionLandmark::apply(Funcdata& fd) {
    uint4 status = Action::STATUS_NONE;
    BlockGraph* bg = fd.getBlockGraph();
    if (!bg) return Action::STATUS_SKIPPED;

    int nblocks = bg->getNumBlocks();
    if (nblocks == 0) return Action::STATUS_SKIPPED;

    // Mark blocks: entry, call sites, merge points, etc.
    for (int i = 0; i < nblocks; i++) {
        PcodeBlockBasic* block = bg->getBlock(i);
        if (!block) continue;

        PcodeOpAST* lastOp = block->getLastOp();
        if (!lastOp) continue;

        int opc = lastOp->getOpcode();
        if (opc == CPUI_CALL || opc == CPUI_CALLIND) {
            block->blocktype = PcodeBlock::CALL;
            applyCount++;
        } else if (opc == CPUI_RETURN) {
            block->blocktype = PcodeBlock::RETURN;
            applyCount++;
        }

        // Mark blocks with multiple predecessors as potential merge points
        if (block->getInSize() > 1) {
            applyCount++;
        }
    }

    if (applyCount > 0) status |= Action::STATUS_APPLIED;
    else status |= Action::STATUS_SKIPPED;
    return status;
}

ActionUnreachable::ActionUnreachable()
    : Action("unreachable", Action::CATEGORY_TRANSFORM, "Remove unreachable blocks") {
}

uint4 ActionUnreachable::apply(Funcdata& fd) {
    uint4 status = Action::STATUS_NONE;
    BlockGraph* bg = fd.getBlockGraph();
    if (!bg || bg->getNumBlocks() <= 1) return Action::STATUS_SKIPPED;

    int nblocks = bg->getNumBlocks();
    std::vector<bool> reachable(nblocks, false);

    // BFS from entry block
    std::vector<int> queue;
    queue.push_back(bg->getStartNode());
    reachable[bg->getStartNode()] = true;

    size_t qidx = 0;
    while (qidx < queue.size()) {
        int cur = queue[qidx++];
        PcodeBlockBasic* block = bg->getBlock(cur);
        if (!block) continue;

        for (int j = 0; j < block->getOutSize(); j++) {
            PcodeBlockBasic* succ = block->getOut(j);
            for (int k = 0; k < nblocks; k++) {
                if (bg->getBlock(k) == succ && !reachable[k]) {
                    reachable[k] = true;
                    queue.push_back(k);
                }
            }
        }
    }

    // Remove unreachable blocks (iterate backwards to preserve indices)
    for (int i = nblocks - 1; i >= 0; i--) {
        if (!reachable[i] && i != bg->getStartNode()) {
            // Move ops from the unreachable block to Funcdata's deletion list
            PcodeBlockBasic* block = bg->getBlock(i);
            if (block) {
                PcodeOpAST* op = block->getFirstOp();
                while (op) {
                    PcodeOpAST* next = nullptr;
                    auto it = op->getBasicIter();
                    if (it != block->end()) {
                        auto nextIt = std::next(it);
                        if (nextIt != block->end()) next = *nextIt;
                    }
                    fd.removeOp(op);
                    op = next;
                }
            }
            bg->removeBlock(i);
            applyCount++;
            status |= Action::STATUS_APPLIED;
        }
    }

    if (applyCount == 0) status |= Action::STATUS_SKIPPED;
    return status;
}

ActionSwitchRecovery::ActionSwitchRecovery()
    : Action("switch_recovery", Action::CATEGORY_TRANSFORM, "Recover switch statements") {
}

uint4 ActionSwitchRecovery::apply(Funcdata& fd) {
    uint4 status = Action::STATUS_NONE;
    BlockGraph* bg = fd.getBlockGraph();
    if (!bg) return Action::STATUS_SKIPPED;

    int nblocks = bg->getNumBlocks();

    for (int i = 0; i < nblocks; i++) {
        PcodeBlockBasic* block = bg->getBlock(i);
        if (!block) continue;

        PcodeOpAST* lastOp = block->getLastOp();
        if (!lastOp) continue;
        if (lastOp->getOpcode() != CPUI_BRANCHIND) continue;

        // Found an indirect branch — potential switch
        // Look for characteristic pattern: load from table + indirect jump
        PcodeOpAST* prev = nullptr;
        auto it = lastOp->getBasicIter();
        if (it != block->begin()) {
            prev = *std::prev(it);
        }

        if (prev && prev->getOpcode() == CPUI_LOAD) {
            block->blocktype = PcodeBlock::SWITCH;
            applyCount++;
            status |= Action::STATUS_APPLIED;
        }
    }

    if (applyCount == 0) status |= Action::STATUS_SKIPPED;
    return status;
}

} // namespace ghidra
