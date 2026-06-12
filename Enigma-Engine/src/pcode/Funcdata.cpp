#include <ghidra/Funcdata.h>
#include <ghidra/HighFunction.h>
#include <ghidra/AddressSpace.h>
#include <algorithm>

namespace ghidra {

Funcdata::Funcdata(const std::string& name, const Address& entry)
    : name(name), entryPoint(entry), bgraph(new BlockGraph()), highFunction(nullptr), ssaConstructed(false) {
    highFunction = new HighFunction(this);
}

Funcdata::~Funcdata() {
    delete bgraph;
    delete highFunction;
    for (auto* op : opList) delete op;
    for (auto* vn : vnList) delete vn;
}

PcodeOpAST* Funcdata::createOp(const Address& addr, int opcode, int numInputs) {
    auto* op = new PcodeOpAST(addr, static_cast<int>(opList.size()), opcode, numInputs);
    opList.push_back(op);
    return op;
}

VarnodeAST* Funcdata::createVarnode(const Address& addr, uint4 size, int32_t id) {
    auto* vn = new VarnodeAST(addr, size, id);
    vnList.push_back(vn);
    return vn;
}

void Funcdata::addOp(PcodeOpAST* op) { opList.push_back(op); }
void Funcdata::addVarnode(VarnodeAST* vn) { vnList.push_back(vn); }

void Funcdata::removeOp(PcodeOpAST* op) {
    // Remove from parent block
    PcodeBlockBasic* parent = op->getParent();
    if (parent) {
        parent->remove(op);
    }

    // Remove descendant links from input varnodes
    for (int i = 0; i < op->getNumInputs(); i++) {
        Varnode* vn = op->getInput(i);
        if (vn) {
            VarnodeAST* vnAst = static_cast<VarnodeAST*>(vn);
            vnAst->removeDescendant(op);
        }
    }

    // Clear output varnode's def if this op defines it
    Varnode* output = op->getOutput();
    if (output) {
        VarnodeAST* outAst = static_cast<VarnodeAST*>(output);
        if (outAst->getDef() == op) {
            outAst->setDef(nullptr);
        }
    }

    // Remove from opList
    auto it = std::find(opList.begin(), opList.end(), op);
    if (it != opList.end()) {
        opList.erase(it);
    }

    // Mark as dead
    op->setDead(true);
}

void Funcdata::replaceVarnode(VarnodeAST* oldVn, VarnodeAST* newVn) {
    for (auto* op : opList) {
        for (int i = 0; i < op->getNumInputs(); i++) {
            if (op->getInput(i) == oldVn) {
                // Skip if replacement would create self-reference:
                // op defines oldVn (which will become newVn) OR already defines newVn
                if (op->getOutput() == oldVn || op->getOutput() == newVn) continue;
                oldVn->removeDescendant(op);
                op->setInput(newVn, i);
                newVn->addDescendant(op);
            }
        }
        if (op->getOutput() == oldVn) {
            op->setOutput(newVn);
        }
    }
}

VarnodeAST* Funcdata::newConstant(uint64_t value, uint4 size) {
    static GenericAddressSpace constSpace("const", 64, AddressSpace::TYPE_CONSTANT, 0);
    Address addr(&constSpace, static_cast<int64_t>(value));
    auto* vn = new VarnodeAST(addr, size, static_cast<int32_t>(vnList.size()));
    vnList.push_back(vn);
    return vn;
}

} // namespace ghidra
