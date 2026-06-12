/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file VarnodeBank.h
/// \brief Container class for VarnodeAST objects, indexed by location.
/// Translated from: ghidra.program.model.pcode.VarnodeBank
#pragma once

#include <ghidra/Address.h>
#include <ghidra/Varnode.h>
#include <ghidra/VarnodeAST.h>
#include <set>
#include <vector>

namespace ghidra {

/// Container that owns and indexes VarnodeAST instances.
/// A single TreeSet (locTree) is kept ordered by a LocComparator so that
/// range queries can be answered in O(log n) using lower_bound/upper_bound.
class VarnodeBank {
public:
    class LocComparator {
    public:
        bool operator()(const VarnodeAST* v1, const VarnodeAST* v2) const;
    };

    class DefComparator {
    public:
        bool operator()(const VarnodeAST* v1, const VarnodeAST* v2) const;
    };

    VarnodeBank();
    ~VarnodeBank();

    void clear();
    int size() const;
    bool isEmpty() const;

    Varnode* create(int s, const Address& addr, int id);
    void destroy(Varnode* vn);
    void makeFree(Varnode* vn);

    Varnode* setInput(Varnode* vn);
    Varnode* setDef(Varnode* vn, PcodeOp* op);

    Varnode* xref(VarnodeAST* vn);

    std::vector<VarnodeAST*> locRange() const;
    std::vector<VarnodeAST*> locRange(const AddressSpace* spaceid) const;
    std::vector<VarnodeAST*> locRange(const Address& addr) const;
    std::vector<VarnodeAST*> locRange(const Address& min, const Address& max) const;
    std::vector<VarnodeAST*> locRange(int sz, const Address& addr) const;

    Varnode* find(int sz, const Address& addr, const Address& pc, int uniq) const;
    Varnode* findInput(int sz, const Address& addr) const;

private:
    typedef std::set<VarnodeAST*, LocComparator> LocSet;
    LocSet locTree_;
};

} // namespace ghidra
