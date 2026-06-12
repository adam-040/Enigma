/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file StructuredBlock.h
/// \brief Structured control-flow block family: PcodeBlock, BlockEdge, BlockGraph,
///        BlockCopy, BlockList, BlockCondition, BlockGoto, BlockIfGoto, BlockProperIf,
///        BlockIfElse, BlockDoWhile, BlockWhileDo, BlockInfLoop, BlockSwitch, BlockMultiGoto,
///        BlockMap.
/// Translated from: ghidra.program.model.pcode.PcodeBlock (and all Block* subclasses)
#pragma once

#include "ghidra/Address.h"
#include "ghidra/AddressFactory.h"
#include "ghidra/Encoder.h"
#include "ghidra/Decoder.h"
#include "ghidra/PcodeException.h"
#include <ghidra/PcodeOp.h>
#include <vector>
#include <string>
#include <memory>
#include <stdexcept>

namespace ghidra {

class StructuredBlock;
class BlockGraph;

class BlockMap {
public:
    struct GotoReference {
        StructuredBlock* gotoblock;
        int rootindex;
        int depth;
        GotoReference(StructuredBlock* gblock, int root, int d)
            : gotoblock(gblock), rootindex(root), depth(d) {}
    };

    explicit BlockMap(AddressFactory* fac);
    BlockMap(const BlockMap& op2);

    AddressFactory* getAddressFactory() const { return factory; }

    StructuredBlock* findLevelBlock(int ind);
    void sortLevelList();
    StructuredBlock* createBlock(const std::string& name, int index);
    void addGotoRef(StructuredBlock* gblock, int root, int depth);
    void resolveGotoReferences();

private:
    AddressFactory* factory;
    std::vector<StructuredBlock*> sortlist;
    std::vector<StructuredBlock*> leaflist;
    std::vector<GotoReference> gotoreflist;
};

class BlockEdge {
public:
    int label;
    StructuredBlock* point;
    int reverse_index;

    BlockEdge(StructuredBlock* pt, int lab, int rev)
        : label(lab), point(pt), reverse_index(rev) {}
    BlockEdge() : label(0), point(nullptr), reverse_index(0) {}

    void encode(Encoder& encoder) const;
    void decode(Decoder& decoder, BlockMap& resolver);
};

class StructuredBlock {
public:
    static constexpr int PLAIN = 0;
    static constexpr int BASIC = 1;
    static constexpr int GRAPH = 2;
    static constexpr int COPY = 3;
    static constexpr int GOTO = 4;
    static constexpr int MULTIGOTO = 5;
    static constexpr int LIST = 6;
    static constexpr int CONDITION = 7;
    static constexpr int PROPERIF = 8;
    static constexpr int IFELSE = 9;
    static constexpr int IFGOTO = 10;
    static constexpr int WHILEDO = 11;
    static constexpr int DOWHILE = 12;
    static constexpr int SWITCH = 13;
    static constexpr int INFLOOP = 14;

    static const char* typeToName(int type);
    static int nameToType(const std::string& name);

    int index;
    int blocktype;
    StructuredBlock* parent;
    std::vector<BlockEdge> intothis;
    std::vector<BlockEdge> outofthis;

    StructuredBlock();
    virtual ~StructuredBlock() = default;

    int getType() const { return blocktype; }
    virtual Address getStart() const { return Address::NO_ADDRESS; }
    virtual Address getStop() const { return Address::NO_ADDRESS; }
    void setIndex(int i) { index = i; }
    int getIndex() const { return index; }
    StructuredBlock* getParent() const { return parent; }

    void addInEdge(StructuredBlock* b, int lab);
    void decodeNextInEdge(Decoder& decoder, BlockMap& resolver);

    StructuredBlock* getIn(int i) const { return intothis[i].point; }
    StructuredBlock* getOut(int i) const { return outofthis[i].point; }
    int getOutRevIndex(int i) const { return outofthis[i].reverse_index; }
    int getInRevIndex(int i) const { return intothis[i].reverse_index; }
    StructuredBlock* getFalseOut() const { return outofthis[0].point; }
    StructuredBlock* getTrueOut() const { return outofthis[1].point; }
    int getInSize() const { return (int)intothis.size(); }
    int getOutSize() const { return (int)outofthis.size(); }

    int calcDepth(const StructuredBlock* leaf) const;
    StructuredBlock* getFrontLeaf() const;

    std::string toString() const;

    virtual void encodeHeader(Encoder& encoder) const;
    virtual void decodeHeader(Decoder& decoder);
    virtual void encodeBody(Encoder& encoder) const;
    virtual void encodeEdges(Encoder& encoder) const;
    virtual void decodeBody(Decoder& decoder, BlockMap& resolver);
    virtual void decodeEdges(Decoder& decoder, BlockMap& resolver);

    void encode(Encoder& encoder) const;
    void decode(Decoder& decoder, BlockMap& resolver);
};

class StructuredBlockGraph : public StructuredBlock {
public:
    StructuredBlockGraph() { blocktype = StructuredBlock::GRAPH; }

    virtual void addBlock(StructuredBlock* bl);
    void setIndices();
    int getSize() const { return (int)blocks.size(); }
    StructuredBlock* getBlock(int i) const { return blocks[i].get(); }
    void addEdge(StructuredBlock* begin, StructuredBlock* end) { end->addInEdge(begin, 0); }
    void transferObjectRef(StructuredBlockGraph* ingraph);

    void encodeBody(Encoder& encoder) const override;
    void decodeBody(Decoder& decoder, BlockMap& resolver) override;
    void decode(Decoder& decoder);

private:
    std::vector<std::unique_ptr<StructuredBlock>> blocks;
    int maxindex;
};

class BlockCopy : public StructuredBlock {
public:
    BlockCopy();
    BlockCopy(void* r, const Address& addr);

    Address getStart() const override { return address; }
    Address getStop() const override { return address; }
    void* getRef() const { return ref; }
    int getAltIndex() const { return altindex; }
    void setRefForTransfer(void* r, const Address& addr) { ref = r; address = addr; }

    void encodeHeader(Encoder& encoder) const override;
    void decodeHeader(Decoder& decoder) override;

private:
    void* ref;
    Address address;
    int altindex;
};

class BlockList : public StructuredBlockGraph {
public:
    BlockList() { blocktype = StructuredBlock::LIST; }
};

class BlockCondition : public StructuredBlockGraph {
public:
    BlockCondition() { blocktype = StructuredBlock::CONDITION; opcode = PcodeOp::BOOL_AND; }

    int getOpcode() const { return opcode; }
    void encodeHeader(Encoder& encoder) const override;
    void decodeHeader(Decoder& decoder) override;

private:
    int opcode;
};

class BlockGoto : public StructuredBlockGraph {
public:
    BlockGoto() { blocktype = StructuredBlock::GOTO; gototarget = nullptr; gototype = 1; }

    StructuredBlock* getGotoTarget() const { return gototarget; }
    int getGotoType() const { return gototype; }
    void setGotoTarget(StructuredBlock* gt) { gototarget = gt; }

    void encodeBody(Encoder& encoder) const override;
    void decodeBody(Decoder& decoder, BlockMap& resolver) override;

private:
    StructuredBlock* gototarget;
    int gototype;
};

class BlockIfGoto : public StructuredBlockGraph {
public:
    BlockIfGoto() { blocktype = StructuredBlock::IFGOTO; gototarget = nullptr; gototype = 1; }

    void setGotoTarget(StructuredBlock* bl) { gototarget = bl; }
    StructuredBlock* getGotoTarget() const { return gototarget; }
    int getGotoType() const { return gototype; }

    void encodeBody(Encoder& encoder) const override;
    void decodeBody(Decoder& decoder, BlockMap& resolver) override;

private:
    StructuredBlock* gototarget;
    int gototype;
};

class BlockProperIf : public StructuredBlockGraph {
public:
    BlockProperIf() { blocktype = StructuredBlock::PROPERIF; }
};

class BlockIfElse : public StructuredBlockGraph {
public:
    BlockIfElse() { blocktype = StructuredBlock::IFELSE; }
};

class BlockDoWhile : public StructuredBlockGraph {
public:
    BlockDoWhile() { blocktype = StructuredBlock::DOWHILE; }
};

class BlockWhileDo : public StructuredBlockGraph {
public:
    BlockWhileDo() { blocktype = StructuredBlock::WHILEDO; }
};

class BlockInfLoop : public StructuredBlockGraph {
public:
    BlockInfLoop() { blocktype = StructuredBlock::INFLOOP; }
};

class BlockSwitch : public StructuredBlockGraph {
public:
    BlockSwitch() { blocktype = StructuredBlock::SWITCH; }
};

class BlockMultiGoto : public StructuredBlockGraph {
public:
    BlockMultiGoto() { blocktype = StructuredBlock::MULTIGOTO; targets.clear(); }

    void addGotoTarget(StructuredBlock* target) { targets.push_back(target); }
    void addBlock(StructuredBlock* target) override;
    int getNumTargets() const { return (int)targets.size(); }
    StructuredBlock* getTarget(int i) const { return targets[i]; }

    void encodeBody(Encoder& encoder) const override;
    void decodeBody(Decoder& decoder, BlockMap& resolver) override;

private:
    std::vector<StructuredBlock*> targets;
};

} // namespace ghidra
