#pragma once

#include <ghidra/AddressSet.h>
#include <vector>
#include <list>
#include <cstdint>

namespace ghidra {

class PcodeOpAST;
class Encoder;
class Decoder;
class BlockMap;
class PcodeBlockBasic;

class PcodeBlockEdge {
public:
    PcodeBlockBasic* src = nullptr;
    PcodeBlockBasic* dest = nullptr;
    int edgeflags = 0;
    
    PcodeBlockEdge() = default;
    PcodeBlockEdge(PcodeBlockBasic* s, PcodeBlockBasic* d, int flags = 0)
        : src(s), dest(d), edgeflags(flags) {}
};

class PcodeBlock {
public:
    enum BlockType { BASIC, CONDITIONAL, SWITCH, CALL, RETURN, INDIRECT, COPY, MAXTYPE };
    BlockType blocktype = BASIC;
    virtual ~PcodeBlock() = default;
    virtual Address getStart() const = 0;
    virtual Address getStop() const = 0;
    virtual void encodeBody(Encoder* encoder) const = 0;
    virtual void decodeBody(Decoder* decoder, BlockMap* resolver) = 0;
};

class PcodeBlockBasic : public PcodeBlock {
public:
    PcodeBlockBasic();
private:
    std::list<PcodeOpAST*> oplist;
    AddressSet cover;
    std::vector<PcodeBlockEdge*> in;
    std::vector<PcodeBlockEdge*> out;

public:
    virtual ~PcodeBlockBasic() = default;

    Address getStart() const override;
    Address getStop() const override;
    bool contains(const Address& addr) const;
    void addCoverRange(const Address& start, const Address& end) { cover.addRange(start, end); }
    void rebuildCoverFromOps();

    void addInEdge(PcodeBlockEdge* edge) { in.push_back(edge); }
    void addOutEdge(PcodeBlockEdge* edge) { out.push_back(edge); }
    const std::vector<PcodeBlockEdge*>& getInEdges() const { return in; }
    const std::vector<PcodeBlockEdge*>& getOutEdges() const { return out; }
    int getInSize() const { return static_cast<int>(in.size()); }
    int getOutSize() const { return static_cast<int>(out.size()); }
    PcodeBlockBasic* getIn(int i) const { return i < static_cast<int>(in.size()) ? in[i]->src : nullptr; }
    PcodeBlockBasic* getOut(int i) const { return i < static_cast<int>(out.size()) ? out[i]->dest : nullptr; }

    void insertBefore(std::list<PcodeOpAST*>::iterator iter, PcodeOpAST* op);
    void insertAfter(std::list<PcodeOpAST*>::iterator iter, PcodeOpAST* op);
    void insertEnd(PcodeOpAST* op);
    void remove(PcodeOpAST* op);

    void encodeBody(Encoder* encoder) const override;
    void decodeBody(Decoder* decoder, BlockMap* resolver) override;

public:
    std::list<PcodeOpAST*>::iterator begin();
    std::list<PcodeOpAST*>::iterator end();
    std::list<PcodeOpAST*>::const_iterator begin() const;
    std::list<PcodeOpAST*>::const_iterator end() const;

    PcodeOpAST* getFirstOp() const;
    PcodeOpAST* getLastOp() const;
};

} // namespace ghidra