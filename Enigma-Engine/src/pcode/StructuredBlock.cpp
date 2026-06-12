/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file StructuredBlock.cpp
/// \brief Implementation of structured control-flow block family
#include "ghidra/StructuredBlock.h"
#include <algorithm>

namespace ghidra {

const char* StructuredBlock::typeToName(int type) {
    switch (type) {
        case PLAIN:   return "plain";
        case BASIC:   return "basic";
        case GRAPH:   return "graph";
        case COPY:    return "plain";
        case GOTO:    return "goto";
        case MULTIGOTO: return "multigoto";
        case LIST:    return "list";
        case CONDITION: return "condition";
        case PROPERIF: return "properif";
        case IFELSE:  return "ifelse";
        case IFGOTO:  return "ifgoto";
        case WHILEDO: return "whiledo";
        case DOWHILE: return "dowhile";
        case SWITCH:  return "switch";
        case INFLOOP: return "infloop";
    }
    return nullptr;
}

int StructuredBlock::nameToType(const std::string& name) {
    if (name.empty()) return -1;
    switch (name[0]) {
        case 'c': return COPY;
        case 'd': return DOWHILE;
        case 'g':
            if (name == "goto") return GOTO;
            return GRAPH;
        case 'i':
            if (name == "ifelse") return IFELSE;
            if (name == "infloop") return INFLOOP;
            return IFGOTO;
        case 'l': return LIST;
        case 'm': return MULTIGOTO;
        case 'p':
            if (name == "properif") return PROPERIF;
            return PLAIN;
        case 's': return SWITCH;
        case 'w': return WHILEDO;
    }
    return -1;
}

StructuredBlock::StructuredBlock()
    : index(-1), blocktype(PLAIN), parent(nullptr) {}

std::string StructuredBlock::toString() const {
    std::string s = typeToName(blocktype);
    s += "@";
    s += getStart().toString();
    return s;
}

void StructuredBlock::addInEdge(StructuredBlock* b, int lab) {
    int ourrev = (int)b->outofthis.size();
    int brev = (int)intothis.size();
    intothis.emplace_back(b, lab, ourrev);
    b->outofthis.emplace_back(this, lab, brev);
}

void StructuredBlock::decodeNextInEdge(Decoder& decoder, BlockMap& resolver) {
    BlockEdge inEdge;
    intothis.push_back(inEdge);
    intothis.back().decode(decoder, resolver);
    StructuredBlock* p = intothis.back().point;
    int rev = intothis.back().reverse_index;
    while ((int)p->outofthis.size() <= rev) {
        p->outofthis.emplace_back(nullptr, 0, 0);
    }
    BlockEdge outEdge(this, 0, (int)intothis.size() - 1);
    p->outofthis[rev] = outEdge;
}

int StructuredBlock::calcDepth(const StructuredBlock* leaf) const {
    int depth = 0;
    while (leaf != this) {
        if (leaf == nullptr) return -1;
        leaf = leaf->parent;
        depth += 1;
    }
    return depth;
}

StructuredBlock* StructuredBlock::getFrontLeaf() const {
    const StructuredBlock* bl = this;
    while (dynamic_cast<const StructuredBlockGraph*>(bl) != nullptr) {
        bl = static_cast<const StructuredBlockGraph*>(bl)->getBlock(0);
    }
    return const_cast<StructuredBlock*>(bl);
}

void StructuredBlock::encodeHeader(Encoder& encoder) const {
    encoder.writeSignedInteger(ATTRIB_INDEX, index);
}

void StructuredBlock::decodeHeader(Decoder& decoder) {
    index = (int)decoder.readSignedInteger(ATTRIB_INDEX);
}

void StructuredBlock::encodeBody(Encoder&) const {}

void StructuredBlock::encodeEdges(Encoder& encoder) const {
    for (const BlockEdge& e : intothis) {
        e.encode(encoder);
    }
}

void StructuredBlock::decodeBody(Decoder&, BlockMap&) {}

void StructuredBlock::decodeEdges(Decoder& decoder, BlockMap& resolver) {
    for (;;) {
        int el = decoder.peekElement();
        if (el != ELEM_EDGE.id) break;
        decodeNextInEdge(decoder, resolver);
    }
}

void StructuredBlock::encode(Encoder& encoder) const {
    encoder.openElement(ELEM_BLOCK);
    encodeHeader(encoder);
    encodeBody(encoder);
    encodeEdges(encoder);
    encoder.closeElement(ELEM_BLOCK);
}

void StructuredBlock::decode(Decoder& decoder, BlockMap& resolver) {
    int el = decoder.openElement(ELEM_BLOCK);
    decodeHeader(decoder);
    decodeBody(decoder, resolver);
    decodeEdges(decoder, resolver);
    decoder.closeElement(el);
}

void BlockEdge::encode(Encoder& encoder) const {
    encoder.openElement(ELEM_EDGE);
    encoder.writeSignedInteger(ATTRIB_END, point->getIndex());
    encoder.writeSignedInteger(ATTRIB_REV, reverse_index);
    encoder.closeElement(ELEM_EDGE);
}

void BlockEdge::decode(Decoder& decoder, BlockMap& resolver) {
    int el = decoder.openElement(ELEM_EDGE);
    label = 0;
    int endIndex = (int)decoder.readSignedInteger(ATTRIB_END);
    point = resolver.findLevelBlock(endIndex);
    if (point == nullptr) {
        throw DecoderException("Bad serialized edge in block graph");
    }
    reverse_index = (int)decoder.readSignedInteger(ATTRIB_REV);
    decoder.closeElement(el);
}

BlockMap::BlockMap(AddressFactory* fac) : factory(fac) {}

BlockMap::BlockMap(const BlockMap& op2) : factory(op2.factory) {
    leaflist = op2.leaflist;
    gotoreflist = op2.gotoreflist;
}

StructuredBlock* BlockMap::findLevelBlock(int ind) {
    int min = 0;
    int max = (int)sortlist.size() - 1;
    while (min <= max) {
        int mid = (min + max) / 2;
        StructuredBlock* block = sortlist[mid];
        if (block->getIndex() == ind) return block;
        if (block->getIndex() < ind) min = mid + 1;
        else max = mid - 1;
    }
    return nullptr;
}

void BlockMap::sortLevelList() {
    std::sort(sortlist.begin(), sortlist.end(),
              [](StructuredBlock* a, StructuredBlock* b) {
                  return a->getIndex() < b->getIndex();
              });
}

StructuredBlock* BlockMap::createBlock(const std::string& name, int index) {
    int btype = StructuredBlock::nameToType(name);
    StructuredBlock* res = nullptr;
    switch (btype) {
        case StructuredBlock::BASIC:      res = new StructuredBlock(); break;
        case StructuredBlock::CONDITION:  res = new BlockCondition(); break;
        case StructuredBlock::COPY:       res = new BlockCopy(); break;
        case StructuredBlock::DOWHILE:    res = new BlockDoWhile(); break;
        case StructuredBlock::GOTO:       res = new BlockGoto(); break;
        case StructuredBlock::GRAPH:      res = new StructuredBlockGraph(); break;
        case StructuredBlock::IFELSE:     res = new BlockIfElse(); break;
        case StructuredBlock::IFGOTO:     res = new BlockIfGoto(); break;
        case StructuredBlock::INFLOOP:    res = new BlockInfLoop(); break;
        case StructuredBlock::LIST:       res = new BlockList(); break;
        case StructuredBlock::MULTIGOTO:  res = new BlockMultiGoto(); break;
        case StructuredBlock::PLAIN:      res = new StructuredBlock(); break;
        case StructuredBlock::PROPERIF:   res = new BlockProperIf(); break;
        case StructuredBlock::SWITCH:     res = new BlockSwitch(); break;
        case StructuredBlock::WHILEDO:    res = new BlockWhileDo(); break;
        default:                          res = new StructuredBlock(); break;
    }
    if (btype == StructuredBlock::PLAIN) res->setIndex(index);
    else res->setIndex(index);
    sortlist.push_back(res);
    if (btype == StructuredBlock::PLAIN || btype == StructuredBlock::COPY ||
        btype == StructuredBlock::BASIC) {
        leaflist.push_back(res);
    }
    return res;
}

void BlockMap::addGotoRef(StructuredBlock* gblock, int root, int depth) {
    gotoreflist.emplace_back(gblock, root, depth);
}

void BlockMap::resolveGotoReferences() {
    std::sort(leaflist.begin(), leaflist.end(),
              [](StructuredBlock* a, StructuredBlock* b) {
                  return a->getIndex() < b->getIndex();
              });
    for (const GotoReference& gotoref : gotoreflist) {
        StructuredBlock* bl = nullptr;
        int lo = 0, hi = (int)leaflist.size() - 1;
        while (lo <= hi) {
            int mid = (lo + hi) / 2;
            if (leaflist[mid]->getIndex() == gotoref.rootindex) {
                bl = leaflist[mid];
                break;
            }
            if (leaflist[mid]->getIndex() < gotoref.rootindex) lo = mid + 1;
            else hi = mid - 1;
        }
        if (bl == nullptr) continue;
        int depth = gotoref.depth;
        while (depth > 0) {
            depth -= 1;
            bl = bl->getParent();
        }
        if (auto* gb = dynamic_cast<BlockGoto*>(gotoref.gotoblock)) {
            gb->setGotoTarget(bl);
        } else if (auto* gb = dynamic_cast<BlockIfGoto*>(gotoref.gotoblock)) {
            gb->setGotoTarget(bl);
        } else if (auto* gb = dynamic_cast<BlockMultiGoto*>(gotoref.gotoblock)) {
            gb->addBlock(bl);
        }
    }
}

void StructuredBlockGraph::addBlock(StructuredBlock* bl) {
    int mn, mx;
    if (dynamic_cast<StructuredBlockGraph*>(bl) != nullptr) {
        StructuredBlockGraph* gbl = static_cast<StructuredBlockGraph*>(bl);
        mn = gbl->index;
        mx = gbl->maxindex;
    } else {
        mn = bl->index;
        mx = mn;
    }
    if (blocks.empty()) {
        index = mn;
        maxindex = mx;
    } else {
        if (mn < index) index = mn;
        if (mx > maxindex) maxindex = mx;
    }
    bl->parent = this;
    blocks.emplace_back(bl);
}

void StructuredBlockGraph::setIndices() {
    for (size_t i = 0; i < blocks.size(); ++i) {
        blocks[i]->index = (int)i;
    }
    index = 0;
    maxindex = (int)blocks.size() - 1;
}

void StructuredBlockGraph::transferObjectRef(StructuredBlockGraph* ingraph) {
    std::vector<StructuredBlockGraph*> queue;
    queue.push_back(this);
    size_t pos = 0;
    while (pos < queue.size()) {
        StructuredBlockGraph* curgraph = queue[pos++];
        int sz = curgraph->getSize();
        for (int i = 0; i < sz; ++i) {
            StructuredBlock* block = curgraph->getBlock(i);
            if (auto* copyblock = dynamic_cast<BlockCopy*>(block)) {
                int altindex = copyblock->getAltIndex();
                if (altindex < ingraph->getSize()) {
                    StructuredBlock* block2 = ingraph->getBlock(altindex);
                    if (auto* copyblock2 = dynamic_cast<BlockCopy*>(block2)) {
                        copyblock->setRefForTransfer(copyblock2->getRef(),
                                                     copyblock2->getStart());
                    }
                }
            } else if (auto* sub = dynamic_cast<StructuredBlockGraph*>(block)) {
                queue.push_back(sub);
            }
        }
    }
}

void StructuredBlockGraph::encodeBody(Encoder& encoder) const {
    StructuredBlock::encodeBody(encoder);
    for (const auto& bl : blocks) {
        encoder.openElement(ELEM_BHEAD);
        encoder.writeSignedInteger(ATTRIB_INDEX, bl->getIndex());
        encoder.writeString(ATTRIB_TYPE, StructuredBlock::typeToName(bl->blocktype));
        encoder.closeElement(ELEM_BHEAD);
    }
    for (const auto& bl : blocks) {
        bl->encode(encoder);
    }
}

void StructuredBlockGraph::decodeBody(Decoder& decoder, BlockMap& resolver) {
    BlockMap newresolver(resolver);
    StructuredBlock::decodeBody(decoder, newresolver);
    std::vector<StructuredBlock*> tmplist;
    for (;;) {
        int el = decoder.peekElement();
        if (el != ELEM_BHEAD.id) break;
        decoder.openElement();
        int ind = (int)decoder.readSignedInteger(ATTRIB_INDEX);
        std::string name = decoder.readString(ATTRIB_TYPE);
        StructuredBlock* newbl = newresolver.createBlock(name, ind);
        tmplist.push_back(newbl);
        decoder.closeElement(el);
    }
    newresolver.sortLevelList();
    for (StructuredBlock* bl : tmplist) {
        bl->decode(decoder, newresolver);
        addBlock(bl);
    }
}

void StructuredBlockGraph::decode(Decoder& decoder) {
    BlockMap resolver(decoder.getAddressFactory());
    StructuredBlock::decode(decoder, resolver);
    resolver.resolveGotoReferences();
}

BlockCopy::BlockCopy() : ref(nullptr), altindex(0) {
    blocktype = StructuredBlock::COPY;
    address = Address::NO_ADDRESS;
}

BlockCopy::BlockCopy(void* r, const Address& addr) : ref(r), address(addr), altindex(0) {
    blocktype = StructuredBlock::COPY;
}

void BlockCopy::encodeHeader(Encoder& encoder) const {
    StructuredBlock::encodeHeader(encoder);
    encoder.writeSignedInteger(ATTRIB_ALTINDEX, altindex);
}

void BlockCopy::decodeHeader(Decoder& decoder) {
    StructuredBlock::decodeHeader(decoder);
    altindex = (int)decoder.readSignedInteger(ATTRIB_ALTINDEX);
}

void BlockCondition::encodeHeader(Encoder& encoder) const {
    StructuredBlock::encodeHeader(encoder);
    encoder.writeString(ATTRIB_OPCODE, PcodeOp::getMnemonic(opcode));
}

void BlockCondition::decodeHeader(Decoder& decoder) {
    StructuredBlock::decodeHeader(decoder);
    std::string opcodename = decoder.readString(ATTRIB_OPCODE);
    try {
        opcode = PcodeOp::getOpcode(opcodename);
    } catch (...) {
        opcode = PcodeOp::BOOL_AND;
    }
}

void BlockGoto::encodeBody(Encoder& encoder) const {
    StructuredBlock::encodeBody(encoder);
    encoder.openElement(ELEM_TARGET);
    StructuredBlock* leaf = gototarget->getFrontLeaf();
    int depth = gototarget->calcDepth(leaf);
    encoder.writeSignedInteger(ATTRIB_INDEX, leaf->getIndex());
    encoder.writeSignedInteger(ATTRIB_DEPTH, depth);
    encoder.writeSignedInteger(ATTRIB_TYPE, gototype);
    encoder.closeElement(ELEM_TARGET);
}

void BlockGoto::decodeBody(Decoder& decoder, BlockMap& resolver) {
    StructuredBlock::decodeBody(decoder, resolver);
    int el = decoder.openElement(ELEM_TARGET);
    int target = (int)decoder.readSignedInteger(ATTRIB_INDEX);
    int depth = (int)decoder.readSignedInteger(ATTRIB_DEPTH);
    gototype = (int)decoder.readUnsignedInteger(ATTRIB_TYPE);
    decoder.closeElement(el);
    gototarget = nullptr;
    resolver.addGotoRef(this, target, depth);
}

void BlockIfGoto::encodeBody(Encoder& encoder) const {
    StructuredBlock::encodeBody(encoder);
    encoder.openElement(ELEM_TARGET);
    StructuredBlock* leaf = gototarget->getFrontLeaf();
    int depth = gototarget->calcDepth(leaf);
    encoder.writeSignedInteger(ATTRIB_INDEX, leaf->getIndex());
    encoder.writeSignedInteger(ATTRIB_DEPTH, depth);
    encoder.writeSignedInteger(ATTRIB_TYPE, gototype);
    encoder.closeElement(ELEM_TARGET);
}

void BlockIfGoto::decodeBody(Decoder& decoder, BlockMap& resolver) {
    StructuredBlock::decodeBody(decoder, resolver);
    int el = decoder.openElement(ELEM_TARGET);
    int target = (int)decoder.readSignedInteger(ATTRIB_INDEX);
    int depth = (int)decoder.readSignedInteger(ATTRIB_DEPTH);
    gototype = (int)decoder.readUnsignedInteger(ATTRIB_TYPE);
    decoder.closeElement(el);
    gototarget = nullptr;
    resolver.addGotoRef(this, target, depth);
}

void BlockMultiGoto::encodeBody(Encoder& encoder) const {
    StructuredBlock::encodeBody(encoder);
    for (StructuredBlock* gototarget : targets) {
        encoder.openElement(ELEM_TARGET);
        StructuredBlock* leaf = gototarget->getFrontLeaf();
        int depth = gototarget->calcDepth(leaf);
        encoder.writeSignedInteger(ATTRIB_INDEX, leaf->getIndex());
        encoder.writeSignedInteger(ATTRIB_DEPTH, depth);
        encoder.closeElement(ELEM_TARGET);
    }
}

void BlockMultiGoto::addBlock(StructuredBlock* target) {
    targets.push_back(target);
    StructuredBlockGraph::addBlock(target);
}

void BlockMultiGoto::decodeBody(Decoder& decoder, BlockMap& resolver) {
    StructuredBlock::decodeBody(decoder, resolver);
    for (;;) {
        int el = decoder.peekElement();
        if (el != ELEM_TARGET.id) break;
        decoder.openElement();
        int target = (int)decoder.readSignedInteger(ATTRIB_INDEX);
        int depth = (int)decoder.readSignedInteger(ATTRIB_DEPTH);
        decoder.closeElement(el);
        resolver.addGotoRef(this, target, depth);
    }
}

} // namespace ghidra

