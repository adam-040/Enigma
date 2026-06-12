#include <ghidra/PcodeBlockBasic.h>
#include <ghidra/PcodeOpAST.h>
#include <ghidra/Encoder.h>
#include <ghidra/Decoder.h>
#include <ghidra/ElementId.h>
#include <ghidra/AttributeId.h>

namespace ghidra {

PcodeBlockBasic::PcodeBlockBasic()
    : PcodeBlock() {
    blocktype = BASIC;
}

Address PcodeBlockBasic::getStart() const {
    return cover.getMinAddress();
}

Address PcodeBlockBasic::getStop() const {
    return cover.getMaxAddress();
}

bool PcodeBlockBasic::contains(const Address& addr) const {
    return cover.contains(addr);
}

void PcodeBlockBasic::insertBefore(std::list<PcodeOpAST*>::iterator iter, PcodeOpAST* op) {
    op->setParent(this);
    op->setDead(false);
    auto newiter = oplist.insert(iter, op);
    op->setBasicIter(newiter);
}

void PcodeBlockBasic::insertAfter(std::list<PcodeOpAST*>::iterator iter, PcodeOpAST* op) {
    op->setParent(this);
    op->setDead(false);
    auto newiter = oplist.insert(std::next(iter), op);
    op->setBasicIter(newiter);
}

void PcodeBlockBasic::insertEnd(PcodeOpAST* op) {
    op->setParent(this);
    op->setDead(false);
    oplist.push_back(op);
    op->setBasicIter(std::prev(oplist.end()));
}

void PcodeBlockBasic::remove(PcodeOpAST* op) {
    op->setParent(nullptr);
    oplist.erase(op->getBasicIter());
}

std::list<PcodeOpAST*>::iterator PcodeBlockBasic::begin() { return oplist.begin(); }
std::list<PcodeOpAST*>::iterator PcodeBlockBasic::end() { return oplist.end(); }
std::list<PcodeOpAST*>::const_iterator PcodeBlockBasic::begin() const { return oplist.begin(); }
std::list<PcodeOpAST*>::const_iterator PcodeBlockBasic::end() const { return oplist.end(); }

void PcodeBlockBasic::encodeBody(Encoder* encoder) const {
    encoder->openElement(ELEM_RANGELIST);
    AddressRangeIterator* iter = cover.getAddressRanges();
    if (iter) {
        while (iter->hasNext()) {
            const AddressRange& range = iter->next();
            encoder->openElement(ELEM_RANGE);
            encoder->writeSpace(ATTRIB_SPACE, range.getAddressSpace());
            encoder->writeUnsignedInteger(ATTRIB_FIRST, range.getMinAddress().getOffset());
            encoder->writeUnsignedInteger(ATTRIB_LAST, range.getMaxAddress().getOffset());
            encoder->closeElement(ELEM_RANGE);
        }
        delete iter;
    }
    encoder->closeElement(ELEM_RANGELIST);
}

void PcodeBlockBasic::decodeBody(Decoder* decoder, BlockMap* resolver) {
    int rangelistel = decoder->openElement(ELEM_RANGELIST);
    while (true) {
        int rangeel = decoder->peekElement();
        if (rangeel != ELEM_RANGE.id) break;
        decoder->openElement(ELEM_RANGE);
        AddressSpace* addressSpace = decoder->readSpace(ATTRIB_SPACE);
        uint64_t offset = decoder->readUnsignedInteger(ATTRIB_FIRST);
        Address start(addressSpace, offset);
        offset = decoder->readUnsignedInteger(ATTRIB_LAST);
        Address stop(addressSpace, offset);
        cover.addRange(start, stop);
        decoder->closeElement(rangeel);
    }
    decoder->closeElement(rangelistel);
}

PcodeOpAST* PcodeBlockBasic::getFirstOp() const {
    if (oplist.empty()) return nullptr;
    return oplist.front();
}

PcodeOpAST* PcodeBlockBasic::getLastOp() const {
    if (oplist.empty()) return nullptr;
    return oplist.back();
}

void PcodeBlockBasic::rebuildCoverFromOps() {
    cover = AddressSet();
    for (auto* op : oplist) {
        Address opAddr = op->getSeqnum().getTarget();
        cover.addRange(opAddr, opAddr);
    }
}

} // namespace ghidra