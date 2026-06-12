#pragma once

#include <ghidra/BlockGraph.h>
#include <ghidra/PcodeOpAST.h>
#include <ghidra/VarnodeAST.h>
#include <string>
#include <vector>

namespace ghidra {

class HighFunction;

class Funcdata {
private:
    std::string name;
    Address entryPoint;
    BlockGraph* bgraph;
    std::vector<PcodeOpAST*> opList;
    std::vector<VarnodeAST*> vnList;
    HighFunction* highFunction;
    bool ssaConstructed;

public:
    Funcdata(const std::string& name, const Address& entry);
    ~Funcdata();

    const std::string& getName() const { return name; }
    const Address& getEntryPoint() const { return entryPoint; }
    BlockGraph* getBlockGraph() const { return bgraph; }
    HighFunction* getHigh() const { return highFunction; }

    PcodeOpAST* createOp(const Address& addr, int opcode, int numInputs);
    VarnodeAST* createVarnode(const Address& addr, uint4 size, int32_t id);

    void addOp(PcodeOpAST* op);
    void addVarnode(VarnodeAST* vn);

    int getNumOps() const { return static_cast<int>(opList.size()); }
    int getNumVarnodes() const { return static_cast<int>(vnList.size()); }

    PcodeOpAST* getOp(int i) const { return opList.at(i); }
    VarnodeAST* getVarnode(int i) const { return vnList.at(i); }

    void removeOp(PcodeOpAST* op);
    void replaceVarnode(VarnodeAST* oldVn, VarnodeAST* newVn);

    VarnodeAST* newConstant(uint64_t value, uint4 size);

    bool hasSSA() const { return ssaConstructed; }
    void setSSA(bool val) { ssaConstructed = val; }
};

} // namespace ghidra
