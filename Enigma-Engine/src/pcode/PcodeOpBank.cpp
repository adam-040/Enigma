/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/PcodeOpBank.h"
#include <algorithm>
#include <limits>

namespace ghidra {

PcodeOpBank::PcodeOpBank() : nextUnique_(0) {}

PcodeOpBank::~PcodeOpBank() {
    clear();
}

int PcodeOpBank::size() const {
    return (int)opTree_.size();
}

void PcodeOpBank::clear() {
    for (auto& kv : opTree_) delete kv.second;
    opTree_.clear();
    deadList_.clear();
    aliveList_.clear();
    nextUnique_ = 0;
}

bool PcodeOpBank::isEmpty() const {
    return opTree_.empty();
}

PcodeOp* PcodeOpBank::create(int opcode, int numinputs, const Address& pc) {
    PcodeOpAST* op = new PcodeOpAST(pc, nextUnique_, opcode, numinputs);
    nextUnique_ += 1;
    opTree_[op->getSeqnum()] = op;
    deadList_.push_back(op);
    op->setInsertIter(std::list<PcodeOpAST*>::iterator());
    return op;
}

PcodeOp* PcodeOpBank::create(int opcode, int numinputs, const SequenceNumber& sq) {
    PcodeOpAST* op = new PcodeOpAST(sq, opcode, numinputs);
    if (sq.getTime() > nextUnique_) {
        nextUnique_ = sq.getTime() + 1;
    }
    opTree_[op->getSeqnum()] = op;
    deadList_.push_back(op);
    op->setInsertIter(std::list<PcodeOpAST*>::iterator());
    return op;
}

void PcodeOpBank::destroy(PcodeOp* op) {
    PcodeOpAST* opast = static_cast<PcodeOpAST*>(op);
    if (!opast->isDead()) return;
    opTree_.erase(op->getSeqnum());
    auto it = std::find(deadList_.begin(), deadList_.end(), opast);
    if (it != deadList_.end()) deadList_.erase(it);
    delete opast;
}

void PcodeOpBank::changeOpcode(PcodeOp* op, int newopc) {
    PcodeOpAST* opast = static_cast<PcodeOpAST*>(op);
    opast->setOpcode(newopc);
}

void PcodeOpBank::markAlive(PcodeOp* op) {
    PcodeOpAST* opast = static_cast<PcodeOpAST*>(op);
    auto it = std::find(deadList_.begin(), deadList_.end(), opast);
    if (it != deadList_.end()) deadList_.erase(it);
    aliveList_.push_back(opast);
    opast->setDead(false);
}

void PcodeOpBank::markDead(PcodeOp* op) {
    PcodeOpAST* opast = static_cast<PcodeOpAST*>(op);
    auto it = std::find(aliveList_.begin(), aliveList_.end(), opast);
    if (it != aliveList_.end()) aliveList_.erase(it);
    deadList_.push_back(opast);
    opast->setDead(true);
}

PcodeOp* PcodeOpBank::findOp(const SequenceNumber& num) const {
    auto it = opTree_.find(num);
    if (it == opTree_.end()) return nullptr;
    return it->second;
}

std::vector<PcodeOpAST*> PcodeOpBank::allOrdered() const {
    std::vector<PcodeOpAST*> res;
    for (auto& kv : opTree_) res.push_back(kv.second);
    return res;
}

std::vector<PcodeOpAST*> PcodeOpBank::allOrdered(const Address& pc) const {
    SequenceNumber lo(pc, 0);
    SequenceNumber hi(pc, std::numeric_limits<int>::max());
    std::vector<PcodeOpAST*> res;
    auto it = opTree_.lower_bound(lo);
    for (; it != opTree_.end(); ++it) {
        if (it->first < hi || it->first == hi) {
            res.push_back(it->second);
        } else {
            break;
        }
    }
    return res;
}

std::vector<PcodeOpAST*> PcodeOpBank::allAlive() const {
    return std::vector<PcodeOpAST*>(aliveList_.begin(), aliveList_.end());
}

std::vector<PcodeOpAST*> PcodeOpBank::allDead() const {
    return std::vector<PcodeOpAST*>(deadList_.begin(), deadList_.end());
}

} // namespace ghidra
