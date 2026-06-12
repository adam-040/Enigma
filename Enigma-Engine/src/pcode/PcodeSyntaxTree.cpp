/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/PcodeSyntaxTree.h"
#include <ghidra/VarnodeAST.h>
#include <ghidra/PcodeOpAST.h>
#include <ghidra/PcodeDataTypeManager.h>
#include <ghidra/VariableStorage.h>
#include <ghidra/HighSymbol.h>
#include <stdexcept>

namespace ghidra {

PcodeSyntaxTree::PcodeSyntaxTree(AddressFactory* afact)
    : addrFactory_(afact), uniqId_(0), refmapDirty_(true), oprefmapDirty_(true),
      dtMgr_(nullptr) {}

PcodeSyntaxTree::~PcodeSyntaxTree() {
    clear();
}

void PcodeSyntaxTree::clear() {
    vbank_.clear();
    opbank_.clear();
    bblocks_.clear();
    refmap_.clear();
    oprefmap_.clear();
    uniqId_ = 0;
    refmapDirty_ = true;
    oprefmapDirty_ = true;
    joinAddrs_.clear();
    joinStorages_.clear();
}

int PcodeSyntaxTree::getNumVarnodes() const {
    return vbank_.size();
}

AddressFactory* PcodeSyntaxTree::getAddressFactory() {
    return addrFactory_;
}

PcodeDataTypeManager* PcodeSyntaxTree::getDataTypeManager() {
    return dtMgr_;
}

Varnode* PcodeSyntaxTree::newVarnode(int sz, const Address& addr) {
    Varnode* vn = vbank_.create(sz, addr, uniqId_);
    uniqId_ += 1;
    if (!refmap_.empty()) {
        refmap_[static_cast<VarnodeAST*>(vn)->getUniqueId()] = vn;
    }
    return vn;
}

Varnode* PcodeSyntaxTree::newVarnode(int sz, const Address& addr, int id) {
    Varnode* vn = vbank_.create(sz, addr, id);
    if (uniqId_ <= id) uniqId_ = id + 1;
    if (!refmap_.empty()) {
        refmap_[id] = vn;
    }
    return vn;
}

Varnode* PcodeSyntaxTree::setInput(Varnode* vn, bool val) {
    if ((!vn->isInput()) && val) {
        return vbank_.setInput(vn);
    }
    if (vn->isInput() && (!val)) {
        vbank_.makeFree(vn);
    }
    return vn;
}

void PcodeSyntaxTree::setAddrTied(Varnode* vn, bool val) {
    VarnodeAST* vnast = static_cast<VarnodeAST*>(vn);
    vnast->setAddrtied(val);
}

void PcodeSyntaxTree::setPersistent(Varnode* vn, bool val) {
    VarnodeAST* vnast = static_cast<VarnodeAST*>(vn);
    vnast->setPersistent(val);
}

void PcodeSyntaxTree::setUnaffected(Varnode* vn, bool val) {
    VarnodeAST* vnast = static_cast<VarnodeAST*>(vn);
    vnast->setUnaffected(val);
}

void PcodeSyntaxTree::setVolatile(Varnode* vn, bool val) {
    VarnodeAST* vnast = static_cast<VarnodeAST*>(vn);
    vnast->setVolatile(val);
}

void PcodeSyntaxTree::setMergeGroup(Varnode* vn, int16_t val) {
    VarnodeAST* vnast = static_cast<VarnodeAST*>(vn);
    vnast->setMergeGroup(val);
}

void PcodeSyntaxTree::setDataType(Varnode* vn, DataType* type) {
    VarnodeAST* vnast = static_cast<VarnodeAST*>(vn);
    vnast->setDataType(type);
}

VariableStorage* PcodeSyntaxTree::getJoinStorage(const std::vector<Varnode*>& pieces) {
    (void)pieces;
    // Full implementation requires PcodeDataTypeManager + Program
    // to assign a join-space Address and a meaningful storage.
    return nullptr;
}

Address PcodeSyntaxTree::getJoinAddress(VariableStorage* storage) {
    if (storage == nullptr) return Address();
    auto it = joinAddrs_.find(storage);
    if (it == joinAddrs_.end()) return Address();
    return it->second;
}

VariableStorage* PcodeSyntaxTree::buildStorage(Varnode* vn) {
    (void)vn;
    return nullptr;
}

HighSymbol* PcodeSyntaxTree::getSymbol(int64_t symbolId) {
    (void)symbolId;
    return nullptr;
}

void PcodeSyntaxTree::buildVarnodeRefs() {
    refmap_.clear();
    auto vns = vbank_.locRange();
    refmap_.reserve(vns.size() * 2);
    for (auto* vn : vns) {
        refmap_[vn->getUniqueId()] = vn;
    }
    refmapDirty_ = false;
}

Varnode* PcodeSyntaxTree::getRef(int id) const {
    if (refmapDirty_) {
        const_cast<PcodeSyntaxTree*>(this)->buildVarnodeRefs();
    }
    auto it = refmap_.find(id);
    if (it == refmap_.end()) return nullptr;
    return it->second;
}

Varnode* PcodeSyntaxTree::getRef(int id) {
    return const_cast<Varnode*>(static_cast<const PcodeSyntaxTree&>(*this).getRef(id));
}

void PcodeSyntaxTree::buildOpRefs() {
    oprefmap_.clear();
    auto ops = opbank_.allOrdered();
    oprefmap_.reserve(ops.size() * 2);
    for (auto* op : ops) {
        oprefmap_[op->getSeqnum().getTime()] = op;
    }
    oprefmapDirty_ = false;
}

PcodeOp* PcodeSyntaxTree::getOpRef(int id) const {
    if (oprefmapDirty_) {
        const_cast<PcodeSyntaxTree*>(this)->buildOpRefs();
    }
    auto it = oprefmap_.find(id);
    if (it == oprefmap_.end()) return nullptr;
    return it->second;
}

PcodeOp* PcodeSyntaxTree::getOpRef(int id) {
    return const_cast<PcodeOp*>(static_cast<const PcodeSyntaxTree&>(*this).getOpRef(id));
}

std::vector<VarnodeAST*> PcodeSyntaxTree::locRange() const {
    return vbank_.locRange();
}

std::vector<VarnodeAST*> PcodeSyntaxTree::getVarnodes(const AddressSpace* spc) const {
    return vbank_.locRange(spc);
}

std::vector<VarnodeAST*> PcodeSyntaxTree::getVarnodes(const Address& addr) const {
    return vbank_.locRange(addr);
}

std::vector<VarnodeAST*> PcodeSyntaxTree::getVarnodes(const Address& min, const Address& max) const {
    return vbank_.locRange(min, max);
}

std::vector<VarnodeAST*> PcodeSyntaxTree::getVarnodes(int sz, const Address& addr) const {
    return vbank_.locRange(sz, addr);
}

Varnode* PcodeSyntaxTree::findVarnode(int sz, const Address& addr, const Address& pc) const {
    return vbank_.find(sz, addr, pc, -1);
}

Varnode* PcodeSyntaxTree::findVarnode(int sz, const Address& addr, const SequenceNumber& sq) const {
    return vbank_.find(sz, addr, sq.getTarget(), sq.getTime());
}

Varnode* PcodeSyntaxTree::findInputVarnode(int sz, const Address& addr) const {
    return vbank_.findInput(sz, addr);
}

std::vector<PcodeOpAST*> PcodeSyntaxTree::getPcodeOps() const {
    return opbank_.allOrdered();
}

std::vector<PcodeOpAST*> PcodeSyntaxTree::getPcodeOps(const Address& addr) const {
    return opbank_.allOrdered(addr);
}

PcodeOp* PcodeSyntaxTree::getPcodeOp(const SequenceNumber& sq) const {
    return opbank_.findOp(sq);
}

std::vector<PcodeBlockBasic*> PcodeSyntaxTree::getBasicBlocks() const {
    return bblocks_;
}

void PcodeSyntaxTree::addBasicBlock(PcodeBlockBasic* bl) {
    bblocks_.push_back(bl);
}

PcodeOp* PcodeSyntaxTree::newOp(const SequenceNumber& sq, int opc,
                                const std::vector<Varnode*>& inputs, Varnode* output) {
    PcodeOp* op = opbank_.create(opc, (int)inputs.size(), sq);
    if (output != nullptr) {
        setOutput(op, output);
    }
    for (size_t i = 0; i < inputs.size(); ++i) {
        setInput(op, inputs[i], (int)i);
    }
    if (!oprefmap_.empty()) {
        oprefmap_[sq.getTime()] = op;
    }
    return op;
}

void PcodeSyntaxTree::setOutput(PcodeOp* op, Varnode* vn) {
    if (vn == op->getOutput()) return;
    if (op->getOutput() != nullptr) {
        unSetOutput(op);
    }
    if (vn->getDef() != nullptr) {
        unSetOutput(vn->getDef());
    }
    vn = vbank_.setDef(vn, op);
    op->setOutput(vn);
}

void PcodeSyntaxTree::unSetOutput(PcodeOp* op) {
    Varnode* vn = op->getOutput();
    if (vn == nullptr) return;
    op->setOutput(nullptr);
    vbank_.makeFree(vn);
}

void PcodeSyntaxTree::setInput(PcodeOp* op, Varnode* vn, int slot) {
    if (slot >= op->getNumInputs()) {
        op->setInput(nullptr, slot);
    }
    if (op->getInput(slot) != nullptr) {
        unSetInput(op, slot);
    }
    if (vn != nullptr) {
        VarnodeAST* vnast = static_cast<VarnodeAST*>(vn);
        vnast->addDescendant(op);
        op->setInput(vnast, slot);
    }
}

void PcodeSyntaxTree::unSetInput(PcodeOp* op, int slot) {
    VarnodeAST* vn = static_cast<VarnodeAST*>(op->getInput(slot));
    vn->removeDescendant(op);
    op->setInput(nullptr, slot);
}

void PcodeSyntaxTree::setOpcode(PcodeOp* op, int opc) {
    opbank_.changeOpcode(op, opc);
}

void PcodeSyntaxTree::insertBefore(PcodeOp* newop, PcodeOp* follow) {
    PcodeOpAST* newopast = static_cast<PcodeOpAST*>(newop);
    PcodeOpAST* followast = static_cast<PcodeOpAST*>(follow);
    PcodeBlockBasic* bblock = followast->getParent();
    bblock->insertBefore(followast->getBasicIter(), newopast);
    opbank_.markAlive(newopast);
}

void PcodeSyntaxTree::insertAfter(PcodeOp* newop, PcodeOp* prev) {
    PcodeOpAST* newopast = static_cast<PcodeOpAST*>(newop);
    PcodeOpAST* prevast = static_cast<PcodeOpAST*>(prev);
    PcodeBlockBasic* bblock = prevast->getParent();
    bblock->insertAfter(prevast->getBasicIter(), newopast);
    opbank_.markAlive(newopast);
}

void PcodeSyntaxTree::unInsert(PcodeOp* op) {
    PcodeOpAST* opast = static_cast<PcodeOpAST*>(op);
    opbank_.markDead(opast);
    opast->getParent()->remove(opast);
}

void PcodeSyntaxTree::deleteOp(PcodeOp* op) {
    opbank_.destroy(op);
}

void PcodeSyntaxTree::unlink(PcodeOpAST* op) {
    unSetOutput(op);
    for (int i = 0; i < op->getNumInputs(); ++i) {
        unSetInput(op, i);
    }
    if (op->getParent() != nullptr) {
        unInsert(op);
    } else {
        opbank_.markDead(op);
    }
}

} // namespace ghidra
