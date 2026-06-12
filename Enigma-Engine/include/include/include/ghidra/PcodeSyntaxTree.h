/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PcodeSyntaxTree.h
/// \brief Coherent graph structure containing Varnodes and PcodeOps.
/// Translated from: ghidra.program.model.pcode.PcodeSyntaxTree
#pragma once

#include <ghidra/Address.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/SequenceNumber.h>
#include <ghidra/Varnode.h>
#include <ghidra/PcodeOp.h>
#include <ghidra/VarnodeBank.h>
#include <ghidra/PcodeOpBank.h>
#include <ghidra/PcodeBlockBasic.h>
#include <ghidra/PcodeFactory.h>
#include <unordered_map>
#include <vector>
#include <memory>

namespace ghidra {

class DataType;
class VariableStorage;
class PcodeDataTypeManager;
class HighSymbol;

/// In-memory collection of Varnodes and PcodeOps forming a coherent graph.
/// Owns the VarnodeBank and PcodeOpBank; provides factory methods for
/// creating new graph nodes. Implements the PcodeFactory interface so
/// it can be used wherever the decompiler-side interface is expected.
///
/// The encoding/decoding paths that depend on a full Program /
/// VariableStorage / PcodeDataTypeManager stack are stubbed until
/// those layers are ported.
class PcodeSyntaxTree : public PcodeFactory {
public:
    PcodeSyntaxTree(AddressFactory* afact = nullptr);
    ~PcodeSyntaxTree() override;

    void clear();

    int getNumVarnodes() const;

    // PcodeFactory implementation
    AddressFactory* getAddressFactory() override;
    PcodeDataTypeManager* getDataTypeManager() override;
    Varnode* newVarnode(int sz, const Address& addr) override;
    Varnode* newVarnode(int sz, const Address& addr, int refId) override;
    VariableStorage* getJoinStorage(const std::vector<Varnode*>& pieces) override;
    Address getJoinAddress(VariableStorage* storage) override;
    VariableStorage* buildStorage(Varnode* vn) override;
    Varnode* getRef(int refid) override;
    PcodeOp* getOpRef(int refid) override;
    HighSymbol* getSymbol(int64_t symbolId) override;
    Varnode* setInput(Varnode* vn, bool val) override;
    void setAddrTied(Varnode* vn, bool val) override;
    void setPersistent(Varnode* vn, bool val) override;
    void setUnaffected(Varnode* vn, bool val) override;
    void setVolatile(Varnode* vn, bool val) override;
    void setMergeGroup(Varnode* vn, int16_t val) override;
    void setDataType(Varnode* vn, DataType* type) override;
    PcodeOp* newOp(const SequenceNumber& sq, int opc,
                   const std::vector<Varnode*>& inputs, Varnode* output) override;

    Varnode* getRef(int id) const;
    PcodeOp* getOpRef(int id) const;

    std::vector<VarnodeAST*> locRange() const;
    std::vector<VarnodeAST*> getVarnodes(const AddressSpace* spc) const;
    std::vector<VarnodeAST*> getVarnodes(const Address& addr) const;
    std::vector<VarnodeAST*> getVarnodes(const Address& min, const Address& max) const;
    std::vector<VarnodeAST*> getVarnodes(int sz, const Address& addr) const;
    Varnode* findVarnode(int sz, const Address& addr, const Address& pc) const;
    Varnode* findVarnode(int sz, const Address& addr, const SequenceNumber& sq) const;
    Varnode* findInputVarnode(int sz, const Address& addr) const;

    std::vector<PcodeOpAST*> getPcodeOps() const;
    std::vector<PcodeOpAST*> getPcodeOps(const Address& addr) const;
    PcodeOp* getPcodeOp(const SequenceNumber& sq) const;

    std::vector<PcodeBlockBasic*> getBasicBlocks() const;

    void setOutput(PcodeOp* op, Varnode* vn);
    void unSetOutput(PcodeOp* op);
    void setInput(PcodeOp* op, Varnode* vn, int slot);
    void unSetInput(PcodeOp* op, int slot);

    void setOpcode(PcodeOp* op, int opc);

    void insertBefore(PcodeOp* newop, PcodeOp* follow);
    void insertAfter(PcodeOp* newop, PcodeOp* prev);

    void unInsert(PcodeOp* op);
    void deleteOp(PcodeOp* op);
    void unlink(PcodeOpAST* op);

    void addBasicBlock(PcodeBlockBasic* bl);

    AddressFactory* getAddressFactory() const { return addrFactory_; }
    VarnodeBank* getVarnodeBank() { return &vbank_; }
    PcodeOpBank* getPcodeOpBank() { return &opbank_; }

    /// Test/debug helper: install (or replace) the data-type manager
    /// the tree reports via PcodeFactory::getDataTypeManager().
    /// The tree does NOT take ownership.
    void setDataTypeManager(PcodeDataTypeManager* mgr) { dtMgr_ = mgr; }

private:
    void buildVarnodeRefs();
    void buildOpRefs();

    AddressFactory* addrFactory_;
    VarnodeBank vbank_;
    PcodeOpBank opbank_;
    std::vector<PcodeBlockBasic*> bblocks_;
    std::unordered_map<int, Varnode*> refmap_;
    std::unordered_map<int, PcodeOp*> oprefmap_;
    int uniqId_;
    bool refmapDirty_;
    bool oprefmapDirty_;
    PcodeDataTypeManager* dtMgr_;
    std::unordered_map<const VariableStorage*, Address> joinAddrs_;
    std::vector<std::unique_ptr<VariableStorage>> joinStorages_;
};

} // namespace ghidra
