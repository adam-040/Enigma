#include <ghidra/JumpTable.h>
#include <ghidra/Funcdata.h>
#include <ghidra/PcodeOpAST.h>
#include <algorithm>

namespace ghidra {

JumpTable::JumpTable(PcodeOpAST* branchInd)
    : branchIndOp(branchInd), tableSize(0), entrySize(4),
      recoveryMode(NOT_RECOVERED), isSwitch(false) {
}

void JumpTable::addSlot(const Address& target, int4 index) {
    JumpSlot slot(target, index);
    slots.push_back(slot);
}

const JumpTable::JumpSlot* JumpTable::getSlot(int4 index) const {
    for (const auto& slot : slots) {
        if (slot.index == index) {
            return &slot;
        }
    }
    return nullptr;
}

Address JumpTable::getTarget(int4 index) const {
    for (const auto& slot : slots) {
        if (slot.index == index) {
            return slot.targetAddr;
        }
    }
    return Address::NO_ADDRESS;
}

bool JumpTable::isReachable(int4 index) const {
    for (const auto& slot : slots) {
        if (slot.index == index) {
            return slot.reachable;
        }
    }
    return false;
}

void JumpTable::clear() {
    slots.clear();
    tableAddr = Address::NO_ADDRESS;
    tableSize = 0;
    entrySize = 4;
    recoveryMode = NOT_RECOVERED;
    isSwitch = false;
}

JumpTableAnalyzer::JumpTableAnalyzer(Funcdata* fd) : funcData(fd) {
}

JumpTableAnalyzer::~JumpTableAnalyzer() {
    for (auto* table : tables) {
        delete table;
    }
    tables.clear();
}

void JumpTableAnalyzer::analyze() {
    if (!funcData) return;

    int4 numOps = funcData->getNumOps();
    for (int4 i = 0; i < numOps; ++i) {
        PcodeOpAST* op = funcData->getOp(i);
        if (op && op->getOpcode() == PcodeOp::BRANCHIND) {
            JumpTable* table = new JumpTable(op);
            tables.push_back(table);
        }
    }
}

JumpTable* JumpTableAnalyzer::findTableForOp(PcodeOpAST* op) const {
    for (auto* table : tables) {
        if (table->getBranchIndOp() == op) {
            return table;
        }
    }
    return nullptr;
}

void JumpTableAnalyzer::clear() {
    for (auto* table : tables) {
        delete table;
    }
    tables.clear();
}

} // namespace ghidra
