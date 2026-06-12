#include <ghidra/FuncCallSpecs.h>
#include <ghidra/Funcdata.h>
#include <algorithm>
#include <map>

namespace ghidra {

void ParamActive::addTrial(VarnodeAST* vn, int4 slot) {
    trials.emplace_back(vn, slot);
}

void ParamActive::clear() {
    trials.clear();
    stackPlaceholderSlot = -1;
    possibleOutput = false;
}

FuncCallSpecs::FuncCallSpecs(PcodeOpAST* callOp)
    : op(callOp), entryAddress(Address::NO_ADDRESS), fd(nullptr),
      effectiveExtraPop(0), stackOffset(OFFSET_UNKNOWN), stackPlaceholderSlot(-1),
      paramShift(0), matchCallCount(1), m_isInputActive(false), m_isOutputActive(false),
      m_isBadJumpTable(false), m_isStackOutputLock(false) {
}

FuncCallSpecs* FuncCallSpecs::clone(PcodeOpAST* newOp) const {
    FuncCallSpecs* clone = new FuncCallSpecs(newOp);
    clone->name = name;
    clone->entryAddress = entryAddress;
    clone->fd = fd;
    clone->effectiveExtraPop = effectiveExtraPop;
    clone->stackOffset = stackOffset;
    clone->stackPlaceholderSlot = stackPlaceholderSlot;
    clone->paramShift = paramShift;
    clone->matchCallCount = matchCallCount;
    clone->m_isInputActive = m_isInputActive;
    clone->m_isOutputActive = m_isOutputActive;
    clone->m_isBadJumpTable = m_isBadJumpTable;
    clone->m_isStackOutputLock = m_isStackOutputLock;
    return clone;
}

void FuncCallSpecs::countMatchingCalls(const std::vector<FuncCallSpecs*>& qlst) {
    std::map<Address, int> countMap;
    for (const auto* fcs : qlst) {
        if (fcs && fcs->getEntryAddress().isValid()) {
            countMap[fcs->getEntryAddress()]++;
        }
    }
    for (auto* fcs : qlst) {
        if (fcs && fcs->getEntryAddress().isValid()) {
            fcs->matchCallCount = countMap[fcs->getEntryAddress()];
        }
    }
}

} // namespace ghidra
