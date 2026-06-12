#include <ghidra/TypePropagation.h>
#include <ghidra/PointerDataType.h>
#include <ghidra/OpCode.h>

namespace ghidra {

TypePropagation::TypePropagation(Funcdata& func, TypeFactory* factory)
    : fd(func), typeFactory(factory) {
}

void TypePropagation::enqueue(VarnodeAST* vn) {
    if (!vn) return;
    if (inQueue.find(vn) == inQueue.end()) {
        workQueue.push(vn);
        inQueue.insert(vn);
    }
}

DataType* TypePropagation::getType(VarnodeAST* vn) {
    if (!vn) return nullptr;
    if (vn->getHigh() && vn->getHigh()->getDataType()) {
        return vn->getHigh()->getDataType();
    }
    auto it = localTypes.find(vn);
    if (it != localTypes.end()) {
        return it->second;
    }
    return nullptr;
}

bool TypePropagation::setType(VarnodeAST* vn, DataType* dt) {
    if (!vn || !dt) return false;
    DataType* current = getType(vn);
    if (current == dt) return false;
    
    if (vn->getHigh()) {
        vn->getHigh()->setDataType(dt);
    } else {
        localTypes[vn] = dt;
    }
    return true;
}

bool TypePropagation::updateVarnodeType(VarnodeAST* vn, DataType* type) {
    if (!vn || !type) return false;
    if (setType(vn, type)) {
        enqueue(vn);
        return true;
    }
    return false;
}

int4 TypePropagation::propagate() {
    int4 totalApplied = 0;
    
    // Enqueue all varnodes initially
    for (int i = 0; i < fd.getNumVarnodes(); i++) {
        enqueue(fd.getVarnode(i));
    }
    
    int maxIterations = 1000;
    int iter = 0;
    while (!workQueue.empty() && iter < maxIterations) {
        iter++;
        VarnodeAST* vn = workQueue.front();
        workQueue.pop();
        inQueue.erase(vn);
        
        PcodeOp* def = vn->getDef();
        if (def) {
            PcodeOpAST* astDef = dynamic_cast<PcodeOpAST*>(def);
            if (astDef) {
                if (propagateOp(astDef)) {
                    totalApplied++;
                }
            }
        }
        
        // Propagate to its descendants
        for (PcodeOp* desc : vn->getDescendants()) {
            PcodeOpAST* astDesc = dynamic_cast<PcodeOpAST*>(desc);
            if (astDesc) {
                if (propagateOp(astDesc)) {
                    totalApplied++;
                }
            }
        }
    }
    
    return totalApplied;
}

bool TypePropagation::propagateOp(PcodeOpAST* op) {
    if (!op) return false;
    OpCode opcode = static_cast<OpCode>(op->getOpcode());
    
    switch (opcode) {
        case OpCode::CPUI_COPY:
            return propagateCopy(op);
        case OpCode::CPUI_LOAD:
            return propagateLoad(op);
        case OpCode::CPUI_STORE:
            return propagateStore(op);
        case OpCode::CPUI_INT_ADD:
            return propagateAdd(op);
        case OpCode::CPUI_INT_EQUAL:
        case OpCode::CPUI_INT_NOTEQUAL:
        case OpCode::CPUI_INT_LESS:
        case OpCode::CPUI_INT_SLESS:
        case OpCode::CPUI_INT_LESSEQUAL:
        case OpCode::CPUI_INT_SLESSEQUAL:
            return propagateCompare(op);
        default:
            break;
    }
    return false;
}

bool TypePropagation::propagateCopy(PcodeOpAST* op) {
    VarnodeAST* input = dynamic_cast<VarnodeAST*>(op->getInput(0));
    VarnodeAST* output = dynamic_cast<VarnodeAST*>(op->getOutput());
    if (!input || !output) return false;
    
    DataType* inType = getType(input);
    DataType* outType = getType(output);
    
    bool changed = false;
    if (inType && !outType) {
        changed |= updateVarnodeType(output, inType);
    } else if (outType && !inType) {
        changed |= updateVarnodeType(input, outType);
    }
    return changed;
}

bool TypePropagation::propagateLoad(PcodeOpAST* op) {
    VarnodeAST* address = dynamic_cast<VarnodeAST*>(op->getInput(1));
    VarnodeAST* output = dynamic_cast<VarnodeAST*>(op->getOutput());
    if (!address || !output) return false;
    
    DataType* addrType = getType(address);
    DataType* outType = getType(output);
    
    bool changed = false;
    if (addrType) {
        auto* ptrType = dynamic_cast<PointerDataType*>(addrType);
        if (ptrType && ptrType->getDataType()) {
            changed |= updateVarnodeType(output, ptrType->getDataType());
        }
    } else if (outType) {
        int ptrSize = 4;
        if (typeFactory) {
            PointerDataType* ptr = typeFactory->getTypePointer(ptrSize, outType, outType->getName() + " *");
            changed |= updateVarnodeType(address, ptr);
        }
    }
    return changed;
}

bool TypePropagation::propagateStore(PcodeOpAST* op) {
    VarnodeAST* address = dynamic_cast<VarnodeAST*>(op->getInput(1));
    VarnodeAST* value = dynamic_cast<VarnodeAST*>(op->getInput(2));
    if (!address || !value) return false;
    
    DataType* addrType = getType(address);
    DataType* valType = getType(value);
    
    bool changed = false;
    if (addrType) {
        auto* ptrType = dynamic_cast<PointerDataType*>(addrType);
        if (ptrType && ptrType->getDataType()) {
            changed |= updateVarnodeType(value, ptrType->getDataType());
        }
    } else if (valType) {
        int ptrSize = 4;
        if (typeFactory) {
            PointerDataType* ptr = typeFactory->getTypePointer(ptrSize, valType, valType->getName() + " *");
            changed |= updateVarnodeType(address, ptr);
        }
    }
    return changed;
}

bool TypePropagation::propagateAdd(PcodeOpAST* op) {
    VarnodeAST* in0 = dynamic_cast<VarnodeAST*>(op->getInput(0));
    VarnodeAST* in1 = dynamic_cast<VarnodeAST*>(op->getInput(1));
    VarnodeAST* output = dynamic_cast<VarnodeAST*>(op->getOutput());
    if (!in0 || !output) return false;
    
    DataType* in0Type = getType(in0);
    DataType* in1Type = in1 ? getType(in1) : nullptr;
    DataType* outType = getType(output);
    
    bool changed = false;
    if (in0Type && dynamic_cast<PointerDataType*>(in0Type)) {
        changed |= updateVarnodeType(output, in0Type);
    } else if (outType && dynamic_cast<PointerDataType*>(outType)) {
        changed |= updateVarnodeType(in0, outType);
    }
    if (in1 && in1Type && dynamic_cast<PointerDataType*>(in1Type)) {
        changed |= updateVarnodeType(output, in1Type);
    }
    return changed;
}

bool TypePropagation::propagateCompare(PcodeOpAST* op) {
    VarnodeAST* in0 = dynamic_cast<VarnodeAST*>(op->getInput(0));
    VarnodeAST* in1 = dynamic_cast<VarnodeAST*>(op->getInput(1));
    VarnodeAST* output = dynamic_cast<VarnodeAST*>(op->getOutput());
    if (!output) return false;
    
    bool changed = false;
    if (typeFactory) {
        changed |= updateVarnodeType(output, typeFactory->getBool());
    }
    
    if (in0 && in1) {
        DataType* in0Type = getType(in0);
        DataType* in1Type = getType(in1);
        if (in0Type && !in1Type) {
            changed |= updateVarnodeType(in1, in0Type);
        } else if (in1Type && !in0Type) {
            changed |= updateVarnodeType(in0, in1Type);
        }
    }
    return changed;
}

} // namespace ghidra
