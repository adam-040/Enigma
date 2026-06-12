/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PcodeOpBank.h
/// \brief Container for PcodeOpAST objects, indexed by SequenceNumber.
/// Translated from: ghidra.program.model.pcode.PcodeOpBank
#pragma once

#include <ghidra/Address.h>
#include <ghidra/SequenceNumber.h>
#include <ghidra/PcodeOp.h>
#include <ghidra/PcodeOpAST.h>
#include <map>
#include <list>
#include <vector>

namespace ghidra {

/// Container that owns and indexes PcodeOpAST instances by SequenceNumber.
/// Keeps two linked lists (deadList and aliveList) to support iteration in
/// insertion order with stable iterators that can be invalidated when ops
/// transition between dead/alive.
class PcodeOpBank {
public:
    PcodeOpBank();
    ~PcodeOpBank();

    int size() const;
    void clear();
    bool isEmpty() const;

    PcodeOp* create(int opcode, int numinputs, const Address& pc);
    PcodeOp* create(int opcode, int numinputs, const SequenceNumber& sq);

    void destroy(PcodeOp* op);
    void changeOpcode(PcodeOp* op, int newopc);

    void markAlive(PcodeOp* op);
    void markDead(PcodeOp* op);

    PcodeOp* findOp(const SequenceNumber& num) const;

    std::vector<PcodeOpAST*> allOrdered() const;
    std::vector<PcodeOpAST*> allOrdered(const Address& pc) const;
    std::vector<PcodeOpAST*> allAlive() const;
    std::vector<PcodeOpAST*> allDead() const;

private:
    typedef std::map<SequenceNumber, PcodeOpAST*> OpTree;
    OpTree opTree_;
    std::list<PcodeOpAST*> deadList_;
    std::list<PcodeOpAST*> aliveList_;
    int nextUnique_;
};

} // namespace ghidra
