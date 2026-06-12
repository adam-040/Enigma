/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/VarnodeBank.h"
#include <ghidra/PcodeOp.h>
#include <ghidra/PcodeOpAST.h>
#include <ghidra/AddressSpace.h>
#include <algorithm>
#include <limits>

namespace ghidra {

bool VarnodeBank::LocComparator::operator()(const VarnodeAST* v1, const VarnodeAST* v2) const {
    int cmp = v1->getAddress().operator<(v2->getAddress()) ? -1 :
              (v1->getAddress().operator==(v2->getAddress()) ? 0 : 1);
    if (cmp != 0) return cmp < 0;
    if (v1->getSize() != v2->getSize()) {
        return v1->getSize() < v2->getSize();
    }
    if (v1->isInput()) {
        if (v2->isInput()) return false;
        return true;
    }
    if (v2->isInput()) return false;
    PcodeOp* def1 = v1->getDef();
    PcodeOp* def2 = v2->getDef();
    if (def1 != nullptr) {
        if (def2 == nullptr) return true;
        if (def1->getSeqnum().getTime() != def2->getSeqnum().getTime()) {
            return def1->getSeqnum().getTime() < def2->getSeqnum().getTime();
        }
        return false;
    }
    if (def2 != nullptr) return false;
    if (v1->getUniqueId() != v2->getUniqueId()) {
        return v1->getUniqueId() < v2->getUniqueId();
    }
    return false;
}

bool VarnodeBank::DefComparator::operator()(const VarnodeAST* v1, const VarnodeAST* v2) const {
    if (v1->isInput()) {
        if (!v2->isInput()) return true;
    } else if (v1->getDef() != nullptr) {
        if (v2->isInput()) return false;
        if (v2->isFree()) return true;
        if (v1->getDef()->getSeqnum().getTime() != v2->getDef()->getSeqnum().getTime()) {
            return v1->getDef()->getSeqnum().getTime() < v2->getDef()->getSeqnum().getTime();
        }
    }
    if (v1->getAddress().operator<(v2->getAddress())) return true;
    if (v2->getAddress().operator<(v1->getAddress())) return false;
    if (v1->getSize() != v2->getSize()) {
        return v1->getSize() < v2->getSize();
    }
    if (v1->isFree()) {
        if (v1->getUniqueId() != v2->getUniqueId()) {
            return v1->getUniqueId() < v2->getUniqueId();
        }
        return false;
    }
    return false;
}

VarnodeBank::VarnodeBank() : locTree_(LocComparator()) {}

VarnodeBank::~VarnodeBank() {
    clear();
}

void VarnodeBank::clear() {
    for (auto* vn : locTree_) delete vn;
    locTree_.clear();
}

int VarnodeBank::size() const {
    return (int)locTree_.size();
}

bool VarnodeBank::isEmpty() const {
    return locTree_.empty();
}

Varnode* VarnodeBank::create(int s, const Address& addr, int id) {
    VarnodeAST* vn = new VarnodeAST(addr, s, id);
    locTree_.insert(vn);
    return vn;
}

void VarnodeBank::destroy(Varnode* vn) {
    auto* vnast = static_cast<VarnodeAST*>(vn);
    auto it = locTree_.find(vnast);
    if (it != locTree_.end()) {
        locTree_.erase(it);
        delete *it;
    }
}

Varnode* VarnodeBank::xref(VarnodeAST* vn) {
    auto it = locTree_.lower_bound(vn);
    if (it != locTree_.end() && (*it)->getAddress() == vn->getAddress() &&
        (*it)->getSize() == vn->getSize() && **it == *vn) {
        (*it)->descendReplace(vn);
        return *it;
    }
    locTree_.insert(vn);
    return vn;
}

void VarnodeBank::makeFree(Varnode* vn) {
    auto* vn1 = static_cast<VarnodeAST*>(vn);
    locTree_.erase(vn1);
    vn1->setDef(nullptr);
    vn1->setInput(false);
    vn1->setFree(true);
    locTree_.insert(vn1);
}

Varnode* VarnodeBank::setInput(Varnode* vn) {
    if (!vn->isFree()) return nullptr;
    if (vn->isConstant()) return nullptr;
    auto* vn1 = static_cast<VarnodeAST*>(vn);
    locTree_.erase(vn1);
    vn1->setInput(true);
    return xref(vn1);
}

Varnode* VarnodeBank::setDef(Varnode* vn, PcodeOp* op) {
    if (!vn->isFree()) return nullptr;
    if (vn->isConstant()) return nullptr;
    auto* vn1 = static_cast<VarnodeAST*>(vn);
    locTree_.erase(vn1);
    vn1->setDef(op);
    return xref(vn1);
}

std::vector<VarnodeAST*> VarnodeBank::locRange() const {
    std::vector<VarnodeAST*> res;
    for (auto* vn : locTree_) res.push_back(vn);
    return res;
}

std::vector<VarnodeAST*> VarnodeBank::locRange(const AddressSpace* spaceid) const {
    Address min = Address(const_cast<AddressSpace*>(spaceid), 0);
    Address max = Address(const_cast<AddressSpace*>(spaceid), (int64_t)0x7FFFFFFFFFFFFFFFLL);
    VarnodeAST lo(min, 0, 0);
    lo.setInput(true);
    VarnodeAST hi(max, std::numeric_limits<int>::max(), 0);
    std::vector<VarnodeAST*> res;
    auto it = locTree_.lower_bound(&lo);
    for (; it != locTree_.end(); ++it) {
        if (LocComparator()(*it, &hi)) res.push_back(*it);
        else break;
    }
    return res;
}

std::vector<VarnodeAST*> VarnodeBank::locRange(const Address& addr) const {
    VarnodeAST lo(addr, 0, 0);
    lo.setInput(true);
    VarnodeAST hi(addr.add(1), 0, 0);
    hi.setInput(true);
    std::vector<VarnodeAST*> res;
    auto it = locTree_.lower_bound(&lo);
    for (; it != locTree_.end(); ++it) {
        if (LocComparator()(*it, &hi)) res.push_back(*it);
        else break;
    }
    return res;
}

std::vector<VarnodeAST*> VarnodeBank::locRange(const Address& min, const Address& max) const {
    VarnodeAST lo(min, 0, 0);
    lo.setInput(true);
    VarnodeAST hi(max, std::numeric_limits<int>::max(), 0);
    std::vector<VarnodeAST*> res;
    auto it = locTree_.lower_bound(&lo);
    for (; it != locTree_.end(); ++it) {
        if (LocComparator()(*it, &hi)) res.push_back(*it);
        else break;
    }
    return res;
}

std::vector<VarnodeAST*> VarnodeBank::locRange(int sz, const Address& addr) const {
    VarnodeAST lo(addr, sz, 0);
    lo.setInput(true);
    VarnodeAST hi(addr, sz + 1, 0);
    hi.setInput(true);
    std::vector<VarnodeAST*> res;
    auto it = locTree_.lower_bound(&lo);
    for (; it != locTree_.end(); ++it) {
        if (LocComparator()(*it, &hi)) res.push_back(*it);
        else break;
    }
    return res;
}

Varnode* VarnodeBank::find(int sz, const Address& addr, const Address& pc, int uniq) const {
    VarnodeAST search(addr, sz, 0);
    int uq = (uniq == -1) ? 0 : uniq;
    PcodeOpAST op(pc, uq, PcodeOp::COPY, 0);
    search.setDef(&op);
    std::vector<VarnodeAST*> res;
    auto it = locTree_.lower_bound(&search);
    for (; it != locTree_.end(); ++it) {
        VarnodeAST* vn = *it;
        if (vn->getSize() != sz) break;
        if (vn->getAddress() != addr) break;
        PcodeOp* op2 = vn->getDef();
        if (op2 != nullptr && op2->getSeqnum().getTarget() == pc) {
            if (uniq == -1 || op2->getSeqnum().getTime() == uniq) {
                return vn;
            }
        }
    }
    return nullptr;
}

Varnode* VarnodeBank::findInput(int sz, const Address& addr) const {
    VarnodeAST search(addr, sz, 0);
    search.setInput(true);
    auto it = locTree_.lower_bound(&search);
    if (it != locTree_.end()) {
        VarnodeAST* vn = *it;
        if (vn->isInput() && vn->getSize() == sz && vn->getAddress() == addr) {
            return vn;
        }
    }
    return nullptr;
}

} // namespace ghidra
