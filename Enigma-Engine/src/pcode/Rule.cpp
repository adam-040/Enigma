#include <ghidra/Rule.h>
#include <ghidra/Funcdata.h>
#include <ghidra/PcodeOpAST.h>
#include <ghidra/VarnodeAST.h>
#include <ghidra/OpCode.h>
#include <algorithm>

namespace ghidra {

Rule::Rule(const std::string& nm, RuleType t)
    : name(nm), type(t), enabled(true), applyCount(0) {
}

RuleConstant::RuleConstant() : Rule("constant_fold", RULE_CONSTANT) {}

bool RuleConstant::applyOp(PcodeOpAST* op, Funcdata& fd) {
    if (!op || !op->getOutput()) return false;
    if (op->isDead()) return false;

    int opc = op->getOpcode();
    if (opc == CPUI_COPY || opc == CPUI_MULTIEQUAL || opc == CPUI_INDIRECT ||
        opc == CPUI_LOAD || opc == CPUI_STORE || opc == CPUI_BRANCH ||
        opc == CPUI_CBRANCH || opc == CPUI_BRANCHIND || opc == CPUI_CALL ||
        opc == CPUI_CALLIND || opc == CPUI_CALLOTHER || opc == CPUI_RETURN) return false;

    bool allConst = true;
    for (int i = 0; i < op->getNumInputs(); i++) {
        Varnode* vn = op->getInput(i);
        if (!vn || !vn->isConstant()) { allConst = false; break; }
    }
    if (!allConst || op->getNumInputs() == 0) return false;

    uint64_t v0 = static_cast<uint64_t>(op->getInput(0)->getOffset());
    uint64_t result = v0;
    if (op->getNumInputs() > 1) {
        uint64_t v1 = static_cast<uint64_t>(op->getInput(1)->getOffset());
        switch (static_cast<OpCode>(opc)) {
            case OpCode::CPUI_INT_ADD:    result = v0 + v1; break;
            case OpCode::CPUI_INT_SUB:    result = v0 - v1; break;
            case OpCode::CPUI_INT_MULT:   result = v0 * v1; break;
            case OpCode::CPUI_INT_DIV:    result = v1 ? v0 / v1 : 0; break;
            case OpCode::CPUI_INT_SDIV:   result = v1 ? static_cast<uint64_t>(static_cast<int64_t>(v0) / static_cast<int64_t>(v1)) : 0; break;
            case OpCode::CPUI_INT_REM:    result = v1 ? v0 % v1 : 0; break;
            case OpCode::CPUI_INT_SREM:   result = v1 ? static_cast<uint64_t>(static_cast<int64_t>(v0) % static_cast<int64_t>(v1)) : 0; break;
            case OpCode::CPUI_INT_AND:    result = v0 & v1; break;
            case OpCode::CPUI_INT_OR:     result = v0 | v1; break;
            case OpCode::CPUI_INT_XOR:    result = v0 ^ v1; break;
            case OpCode::CPUI_INT_LEFT:   result = v0 << (v1 & 0x3f); break;
            case OpCode::CPUI_INT_RIGHT:  result = v0 >> (v1 & 0x3f); break;
            case OpCode::CPUI_INT_SRIGHT: result = static_cast<uint64_t>(static_cast<int64_t>(v0) >> (v1 & 0x3f)); break;
            case OpCode::CPUI_INT_EQUAL:  result = v0 == v1 ? 1 : 0; break;
            case OpCode::CPUI_INT_NOTEQUAL: result = v0 != v1 ? 1 : 0; break;
            case OpCode::CPUI_INT_LESS:   result = v0 < v1 ? 1 : 0; break;
            case OpCode::CPUI_INT_LESSEQUAL: result = v0 <= v1 ? 1 : 0; break;
            case OpCode::CPUI_INT_SLESS:  result = static_cast<int64_t>(v0) < static_cast<int64_t>(v1) ? 1 : 0; break;
            case OpCode::CPUI_INT_SLESSEQUAL: result = static_cast<int64_t>(v0) <= static_cast<int64_t>(v1) ? 1 : 0; break;
            default: return false;
        }
    } else {
        switch (static_cast<OpCode>(opc)) {
            case OpCode::CPUI_INT_NEGATE: result = ~v0; break;
            case OpCode::CPUI_INT_2COMP:  result = ~v0 + 1; break;
            case OpCode::CPUI_BOOL_NEGATE: result = v0 ? 0 : 1; break;
            case OpCode::CPUI_COPY:       result = v0; break;
            default: return false;
        }
    }

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
    return true;
}

RuleCopyPropagate::RuleCopyPropagate() : Rule("copy_propagate", RULE_COPY) {}

bool RuleCopyPropagate::applyOp(PcodeOpAST* op, Funcdata& fd) {
    if (!op || op->isDead()) return false;
    if (static_cast<int>(op->getOpcode()) != static_cast<int>(OpCode::CPUI_COPY)) return false;

    VarnodeAST* input = static_cast<VarnodeAST*>(op->getInput(0));
    VarnodeAST* output = static_cast<VarnodeAST*>(op->getOutput());
    if (!input || !output) return false;
    if (output->hasNoDescend()) return false;

    // Only propagate constants (safe across SSA versions)
    if (!input->isConstant()) return false;

    fd.replaceVarnode(output, input);
    fd.removeOp(op);
    applyCount++;
    return true;
}

RuleDeadCode::RuleDeadCode() : Rule("dead_code", RULE_DEADCODE) {}

bool RuleDeadCode::applyOp(PcodeOpAST* op, Funcdata& fd) {
    if (!op || op->isDead()) return false;

    int opc = op->getOpcode();
    if (opc == CPUI_CALL || opc == CPUI_CALLIND || opc == CPUI_CALLOTHER ||
        opc == CPUI_STORE || opc == CPUI_BRANCH || opc == CPUI_CBRANCH ||
        opc == CPUI_BRANCHIND || opc == CPUI_RETURN) return false;

    Varnode* output = op->getOutput();
    if (!output) return false;

    VarnodeAST* outputAst = static_cast<VarnodeAST*>(output);
    if (outputAst->hasNoDescend() && !outputAst->isPersistent() && !outputAst->isAddrTied()) {
        fd.removeOp(op);
        applyCount++;
        return true;
    }

    return false;
}

RuleMergeVarnodes::RuleMergeVarnodes() : Rule("merge_varnodes", RULE_MERGE) {}

bool RuleMergeVarnodes::applyOp(PcodeOpAST* op, Funcdata& fd) {
    if (!op || op->isDead()) return false;

    VarnodeAST* output = static_cast<VarnodeAST*>(op->getOutput());
    if (!output || !output->isFree() || output->isPersistent() || output->isAddrTied()) return false;
    if (output->hasNoDescend()) return false;

    PcodeOp* loneDesc = output->getLoneDescend();
    if (loneDesc && op->getNumInputs() > 0) {
        VarnodeAST* input = static_cast<VarnodeAST*>(op->getInput(0));
        if (input && input != output) {
            fd.replaceVarnode(output, input);
            fd.removeOp(op);
            applyCount++;
            return true;
        }
    }

    return false;
}

RuleTypePropagation::RuleTypePropagation() : Rule("type_propagation", RULE_TYPEPROP) {}

bool RuleTypePropagation::applyOp(PcodeOpAST* op, Funcdata&) {
    if (!op) return false;

    int opcode = static_cast<int>(op->getOpcode());
    switch (opcode) {
        case static_cast<int>(OpCode::CPUI_INT_MULT):
        case static_cast<int>(OpCode::CPUI_INT_DIV):
        case static_cast<int>(OpCode::CPUI_INT_REM):
        case static_cast<int>(OpCode::CPUI_INT_SDIV):
        case static_cast<int>(OpCode::CPUI_INT_SREM):
            applyCount++;
            return true;
        default:
            return false;
    }
}

RulePushMulti::RulePushMulti() : Rule("push_multi", RULE_TRANSFORM) {}

bool RulePushMulti::applyOp(PcodeOpAST* op, Funcdata& fd) {
    if (!op || op->isDead()) return false;
    if (static_cast<int>(op->getOpcode()) != static_cast<int>(OpCode::CPUI_MULTIEQUAL)) return false;
    if (op->getNumInputs() < 2) return false;

    // Check if all inputs are the same varnode
    Varnode* firstInput = op->getInput(0);
    if (!firstInput) return false;

    for (int i = 1; i < op->getNumInputs(); i++) {
        if (op->getInput(i) != firstInput) return false;
    }

    // All inputs identical: replace MULTIEQUAL with COPY
    VarnodeAST* inputAst = static_cast<VarnodeAST*>(firstInput);
    VarnodeAST* output = static_cast<VarnodeAST*>(op->getOutput());
    if (!output) return false;

    fd.replaceVarnode(output, inputAst);
    fd.removeOp(op);
    applyCount++;
    return true;
}

bool RulePullMulti::applyOp(PcodeOpAST* op, Funcdata& fd) {
    if (!op || op->isDead()) return false;
    if (static_cast<int>(op->getOpcode()) != static_cast<int>(OpCode::CPUI_COPY)) return false;

    VarnodeAST* input = static_cast<VarnodeAST*>(op->getInput(0));
    VarnodeAST* output = static_cast<VarnodeAST*>(op->getOutput());
    if (!input || !output) return false;
    if (output->hasNoDescend()) return false;

    // If input is defined by a MULTIEQUAL, and the COPY is in a successor block,
    // replace the COPY with the MULTIEQUAL's per-predecessor values
    PcodeOp* def = input->getDef();
    if (!def) return false;
    if (static_cast<int>(def->getOpcode()) != static_cast<int>(OpCode::CPUI_MULTIEQUAL)) return false;

    // Simple case: output only has one use; replace that use with the matching input
    fd.replaceVarnode(output, input);
    fd.removeOp(op);
    applyCount++;
    return true;
}

RulePullMulti::RulePullMulti() : Rule("pull_multi", RULE_TRANSFORM) {}

RuleSimplifyBoolean::RuleSimplifyBoolean() : Rule("simplify_boolean", RULE_TRANSFORM) {}

bool RuleSimplifyBoolean::applyOp(PcodeOpAST* op, Funcdata& fd) {
    if (!op || op->isDead()) return false;

    int opcode = static_cast<int>(op->getOpcode());
    if (opcode == static_cast<int>(OpCode::CPUI_BOOL_AND) || opcode == static_cast<int>(OpCode::CPUI_BOOL_OR)) {
        Varnode* input0 = op->getInput(0);
        Varnode* input1 = op->getInput(1);

        if (input0 && input1 && input0->isConstant() && input1->isConstant()) {
            uint64_t v0 = static_cast<uint64_t>(input0->getOffset());
            uint64_t v1 = static_cast<uint64_t>(input1->getOffset());
            uint64_t result = (opcode == static_cast<int>(OpCode::CPUI_BOOL_AND)) ? (v0 && v1) : (v0 || v1);
            VarnodeAST* constVn = fd.newConstant(result, 1);
            op->removeInput(1);
            op->setInput(constVn, 0);
            op->setOpcode(CPUI_COPY);
            constVn->addDescendant(op);
            applyCount++;
            return true;
        }
    }

    return false;
}

RuleUnusedOutput::RuleUnusedOutput() : Rule("unused_output", RULE_DEADCODE) {}

bool RuleUnusedOutput::applyOp(PcodeOpAST* op, Funcdata& fd) {
    if (!op || op->isDead()) return false;

    Varnode* output = op->getOutput();
    if (!output) return false;

    VarnodeAST* outputAst = static_cast<VarnodeAST*>(output);
    if (outputAst->hasNoDescend() && !outputAst->isInput()) {
        fd.removeOp(op);
        applyCount++;
        return true;
    }

    return false;
}

RuleZeroExtension::RuleZeroExtension() : Rule("zero_extension", RULE_TRANSFORM) {}

bool RuleZeroExtension::applyOp(PcodeOpAST* op, Funcdata& fd) {
    if (!op || op->isDead()) return false;

    if (static_cast<int>(op->getOpcode()) == static_cast<int>(OpCode::CPUI_INT_ZEXT)) {
        Varnode* input = op->getInput(0);
        if (input && input->isConstant()) {
            uint64_t val = static_cast<uint64_t>(input->getOffset());
            uint4 sz = op->getOutput()->getSize();
            if (sz == 0) sz = 1;
            uint64_t mask = (sz >= 8) ? ~0ULL : ((1ULL << (sz * 8)) - 1ULL);
            val &= mask;
            VarnodeAST* constVn = fd.newConstant(val, sz);
            op->setInput(constVn, 0);
            constVn->addDescendant(op);
            op->setOpcode(CPUI_COPY);
            applyCount++;
            return true;
        }
    }

    return false;
}

RuleLibrary::RuleLibrary() {
    addRule(new RuleConstant());
    addRule(new RuleCopyPropagate());
    addRule(new RuleDeadCode());
    addRule(new RuleMergeVarnodes());
    addRule(new RuleTypePropagation());
    addRule(new RulePushMulti());
    addRule(new RulePullMulti());
    addRule(new RuleSimplifyBoolean());
    addRule(new RuleUnusedOutput());
    addRule(new RuleZeroExtension());

    rebuildActiveList();
}

RuleLibrary::~RuleLibrary() {
    clear();
}

void RuleLibrary::addRule(Rule* rule) {
    if (rule) rules.push_back(rule);
}

void RuleLibrary::removeRule(Rule* rule) {
    auto it = std::find(rules.begin(), rules.end(), rule);
    if (it != rules.end()) {
        delete *it;
        rules.erase(it);
        rebuildActiveList();
    }
}

void RuleLibrary::clear() {
    for (auto* rule : rules) {
        delete rule;
    }
    rules.clear();
    activeRules.clear();
}

Rule* RuleLibrary::getRule(const std::string& name) const {
    for (auto* rule : rules) {
        if (rule->getName() == name) return rule;
    }
    return nullptr;
}

Rule* RuleLibrary::getRule(int4 index) const {
    if (index >= 0 && index < static_cast<int4>(rules.size())) {
        return rules[index];
    }
    return nullptr;
}

void RuleLibrary::enableAll() {
    for (auto* rule : rules) {
        rule->setEnabled(true);
    }
    rebuildActiveList();
}

void RuleLibrary::disableAll() {
    for (auto* rule : rules) {
        rule->setEnabled(false);
    }
    rebuildActiveList();
}

void RuleLibrary::enableRule(const std::string& name) {
    Rule* rule = getRule(name);
    if (rule) {
        rule->setEnabled(true);
        rebuildActiveList();
    }
}

void RuleLibrary::disableRule(const std::string& name) {
    Rule* rule = getRule(name);
    if (rule) {
        rule->setEnabled(false);
        rebuildActiveList();
    }
}

void RuleLibrary::rebuildActiveList() {
    activeRules.clear();
    for (auto* rule : rules) {
        if (rule->isEnabled()) {
            activeRules.push_back(rule);
        }
    }
}

uint4 RuleLibrary::applyAll(Funcdata& fd) {
    uint4 totalApplied = 0;

    for (int i = fd.getNumOps() - 1; i >= 0; i--) {
        PcodeOpAST* op = fd.getOp(i);
        if (!op) continue;

        for (auto* rule : activeRules) {
            if (rule->applyOp(op, fd)) {
                totalApplied++;
            }
        }
    }

    return totalApplied;
}

uint4 RuleLibrary::applyAllWithContext(Funcdata& fd) {
    return applyAll(fd);
}

} // namespace ghidra
