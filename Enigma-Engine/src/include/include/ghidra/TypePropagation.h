#pragma once

#include <ghidra/Funcdata.h>
#include <ghidra/VarnodeAST.h>
#include <ghidra/PcodeOpAST.h>
#include <ghidra/TypeFactory.h>
#include <ghidra/DataType.h>
#include <queue>
#include <unordered_set>
#include <unordered_map>

namespace ghidra {

class TypePropagation {
private:
    Funcdata& fd;
    TypeFactory* typeFactory;
    std::queue<VarnodeAST*> workQueue;
    std::unordered_set<VarnodeAST*> inQueue;
    std::unordered_map<VarnodeAST*, DataType*> localTypes;

    void enqueue(VarnodeAST* vn);
    bool updateVarnodeType(VarnodeAST* vn, DataType* type);
    
    bool propagateOp(PcodeOpAST* op);
    bool propagateCopy(PcodeOpAST* op);
    bool propagateLoad(PcodeOpAST* op);
    bool propagateStore(PcodeOpAST* op);
    bool propagateAdd(PcodeOpAST* op);
    bool propagateCompare(PcodeOpAST* op);

public:
    TypePropagation(Funcdata& func, TypeFactory* factory);
    ~TypePropagation() = default;

    DataType* getType(VarnodeAST* vn);
    bool setType(VarnodeAST* vn, DataType* dt);

    int4 propagate();
};

} // namespace ghidra
