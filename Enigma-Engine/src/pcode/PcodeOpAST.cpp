#include <ghidra/PcodeOpAST.h>

namespace ghidra {

PcodeOpAST::PcodeOpAST(const SequenceNumber& sq, int op, int numinputs)
    : PcodeOp(sq, op, numinputs, nullptr),
      bDead(false),       // starts alive; setDead(true) marks for removal
      parent(nullptr) {
}

PcodeOpAST::PcodeOpAST(const Address& a, int uq, int op, int numinputs)
    : PcodeOpAST(SequenceNumber(a, uq), op, numinputs) {
}

bool PcodeOpAST::isDead() const {
    return bDead;
}

PcodeBlockBasic* PcodeOpAST::getParent() const {
    return parent;
}

std::list<PcodeOpAST*>::iterator PcodeOpAST::getBasicIter() const {
    return basiciter;
}

std::list<PcodeOpAST*>::iterator PcodeOpAST::getInsertIter() const {
    return insertiter;
}

void PcodeOpAST::setParent(PcodeBlockBasic* par) {
    parent = par;
}

void PcodeOpAST::setBasicIter(std::list<PcodeOpAST*>::iterator iter) {
    basiciter = iter;
}

void PcodeOpAST::setInsertIter(std::list<PcodeOpAST*>::iterator iter) {
    insertiter = iter;
}

} // namespace ghidra