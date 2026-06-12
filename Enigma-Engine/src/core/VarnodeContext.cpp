#include <ghidra/VarnodeContext.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/CompilerSpec.h>
#include <ghidra/Language.h>
#include <ghidra/AddressFactory.h>
#include <iostream>
#include <cstdlib>

namespace ghidra {

VarnodeContext::VarnodeContext(Program* program_, ProgramContext* programContext_,
                               ProgramContext* spaceProgramContext, bool recordStartEndState_)
    : debug(false),
      program(program_),
      BAD_ADDRESS(Address()),
      BAD_VARNODE(BAD_ADDRESS, 0),
      BAD_OFFSET_SPACEID(0),
      SUSPECT_OFFSET_SPACEID(0),
      BAD_SPACE_ID_VALUE(0),
      pointerBitSize(0),
      programContext(programContext_),
      isBE(false),
      recordStartEndState(recordStartEndState_),
      pointerSize(program_->getDefaultPointerSize())
{
    if (pointerSize > 8) pointerSize = 8;

    Language* lang = program->getLanguage();
    if (lang) {
        isBE = lang->isBigEndian();
    }

    if (lang && lang->getAddressFactory()) {
        addrFactory = lang->getAddressFactory();
    }

    pointerBitSize = pointerSize * 8;

    BAD_SPACE_ID_VALUE = getAddressSpace("BAD_ADDRESS_SPACE", pointerBitSize);

    BAD_OFFSET_SPACEID = getAddressSpace("(Bad Address Offset)", pointerBitSize);

    BAD_VARNODE = Varnode(BAD_ADDRESS, 0);

    SUSPECT_OFFSET_SPACEID = getAddressSpace(SUSPECT_CONST_NAME, pointerBitSize);

    this->programContext = programContext_;

    setupValidSymbolicStackNames(program);
}

VarnodeContext::~VarnodeContext() {
    for (auto* vn : allocatedVarnodes) {
        delete vn;
    }
}

void VarnodeContext::setDebug(bool debugOn) { debug = debugOn; }
bool VarnodeContext::getDebug() const { return debug; }

void VarnodeContext::setCurrentInstruction(Instruction* instr) {
    currentInstruction = instr;
}

Instruction* VarnodeContext::getCurrentInstruction(const Address& addr) {
    if (currentInstruction != nullptr) return currentInstruction;
    if (program && program->getListing()) {
        currentInstruction = program->getListing()->getInstructionContaining(addr);
    }
    return currentInstruction;
}

void VarnodeContext::flowToAddress(const Address& fromAddr, const Address& toAddr) {
    currentAddress = toAddr;
    flowToFromLists[toAddr].push_back(fromAddr);
}

void VarnodeContext::flowStart(const Address& toAddr) {
    currentAddress = toAddr;
    if (recordStartEndState) {
        addrStartState[toAddr] = regVals;
        regValsStack.push(regVals);
        regVals.clear();
    }
}

void VarnodeContext::flowEnd(const Address& address) {
    if (recordStartEndState) {
        addrEndState[address] = regVals;
    }
    currentAddress = Address();
}

void VarnodeContext::setupValidSymbolicStackNames(Program* program_) {
    Register* stackRegister = nullptr;
    if (program_ && program_->getCompilerSpec()) {
        stackRegister = program_->getCompilerSpec()->getStackPointer();
    }
    stackReg = stackRegister;
    if (stackRegister == nullptr) return;
    validSymbolicStackNames.insert(stackRegister->getName());
}

// ============================================================================
// Value resolution (main algorithm)
// ============================================================================

Varnode* VarnodeContext::getValue(Varnode* varnode, ContextEvaluator* evaluator) {
    return getValue(varnode, false, evaluator);
}

Varnode* VarnodeContext::getValue(Varnode* varnode, bool signed_, ContextEvaluator* evaluator) {
    if (varnode == nullptr) return nullptr;

    if (isConstant(varnode)) {
        return varnode;
    }

    Varnode* rvnode = nullptr;

    if (varnode->isUnique()) {
        rvnode = getMemoryValue(tempUniqueVals, varnode, signed_);
    } else {
        rvnode = getMemoryValue(tempVals, varnode, signed_);
    }

    if (rvnode != nullptr) {
        if (rvnode->getAddress() == BAD_ADDRESS) return nullptr;
        return rvnode;
    }

    if (isRegister(varnode)) {
        Varnode* value = getMemoryValue(regVals, varnode, signed_);
        if (value != nullptr) {
            if (value->isConstant()) {
                int64_t lvalue = value->getOffset();
                int valSize = value->getSize();

                if (value->getOffset() == -1 || value->getOffset() == 0) {
                    value = createVarnode(lvalue, SUSPECT_OFFSET_SPACEID, valSize);
                } else if (signed_) {
                    int shift = 8 * (8 - valSize);
                    lvalue = (lvalue << shift) >> shift;
                    value = createVarnode(lvalue, value->getSpace(), valSize);
                }
            }
            rvnode = value;
            if (rvnode && !(rvnode->getAddress() == BAD_ADDRESS)) {
                return rvnode;
            }
        }
        return varnode;
    }

    bool isAddr = varnode->isAddress();
    if (isAddr) {
        int64_t varnodeOffset = varnode->getOffset();
        if (varnodeOffset == 0 || varnodeOffset == 0xffffffff || varnodeOffset == -1LL) {
            return nullptr;
        }

        Varnode* lvalue = getMemoryValue(memoryVals, varnode, signed_);
        if (lvalue != nullptr) {
            return lvalue;
        }

        Address addr = varnode->getAddress();

        if (program && program->getListing()) {
            if (program->getListing()->getInstructionContaining(addr) != nullptr) {
                hitDest = true;
            }
        }

        if (program && program->getReferenceManager()) {
            auto refsFrom = program->getReferenceManager()->getReferencesFrom(addr);
            if (!refsFrom.empty() && refsFrom[0]->isExternalReference()) {
                Address external = refsFrom[0]->getToAddress();
                return createVarnode(external.getOffset(),
                                     external.getAddressSpace()->getSpaceID(), 0);
            }
        }

        bool readOnly = isReadOnly(addr);
        if (program && program->getMemory()) {
            int valSize = varnode->getSize();
            try {
                int64_t value = 0;
                Memory* mem = program->getMemory();
                switch (valSize) {
                    case 1: value = mem->getByte(addr) & 0xff; break;
                    case 2: value = mem->getShort(addr) & 0xffff; break;
                    case 4: value = mem->getInt(addr) & 0xffffffffLL; break;
                    case 8: value = static_cast<int64_t>(mem->getLong(addr)); break;
                    default: return nullptr;
                }
                if (value == 0) return nullptr;
                if (signed_) {
                    int shift = 8 * (8 - valSize);
                    value = (value << shift) >> shift;
                }
                int spaceId = readOnly ? 0 : SUSPECT_OFFSET_SPACEID;
                return createVarnode(value, spaceId, valSize);
            } catch (...) {}
        }
    }

    if (evaluator != nullptr && !varnode->isAddress()) {
        Instruction* instr = getCurrentInstruction(currentAddress);
        int64_t* lval = evaluator->unknownValue(this, instr, varnode);
        if (lval == nullptr && !varnode->isUnique()) {
            return varnode;
        }
    }

    return nullptr;
}

void VarnodeContext::putValue(Varnode* out, Varnode* result, bool mustClear) {
    if (out == nullptr) return;
    if (result == nullptr) result = &BAD_VARNODE;

    if (out->isAddress() || isSymbolicSpace(out->getSpace())) {
        if (!isRegister(out)) {
            putMemoryValue(memoryVals, out, result);
            return;
        }
    }

    if (out->isUnique()) {
        putMemoryValue(tempUniqueVals, out, result);
    } else {
        putMemoryValue(tempVals, out, result);
    }
}

void VarnodeContext::propogateResults(bool clearContext) {
    for (auto& [addr, vn] : tempVals) {
        regVals[addr] = vn;
    }
    if (clearContext) {
        tempVals.clear();
        tempUniqueVals.clear();
    }
}

void VarnodeContext::propogateValue(Register* reg, Varnode* node, Varnode* val,
                                     const Address& address) {
    putMemoryValue(regVals, node, val);
}

// ============================================================================
// Memory value operations (byte-level assembly/disassembly)
// ============================================================================

Varnode* VarnodeContext::getMemoryValue(std::map<Address, Varnode*>& valStore,
                                         Varnode* varnode, bool signed_) {
    int size = varnode->getSize();
    Address addr = varnode->getAddress();

    // For 1-byte values, direct lookup
    if (size == 1) {
        auto it = valStore.find(addr);
        if (it != valStore.end()) return it->second;
        return nullptr;
    }

    // Multi-byte: assemble from individual bytes
    std::vector<Varnode*> split(size, nullptr);
    for (int i = 0; i < size; i++) {
        Address byteAddr = addr.addWrap(i);
        auto it = valStore.find(byteAddr);
        if (it == valStore.end()) return nullptr;
        split[i] = it->second;
    }

    // Reassemble
    int64_t value = 0;
    Varnode* typeNode = split[0];
    if (!typeNode->isConstant()) return typeNode;

    for (int i = 0; i < size; i++) {
        int shift = (isBE ? (size - i - 1) : i) * 8;
        value |= (split[i]->getOffset() << shift);
    }

    if (signed_ && size > 0) {
        int shift = (8 - size) * 8;
        value = (value << shift) >> shift;
    }
    return createConstantVarnode(value, size);
}

void VarnodeContext::putMemoryValue(std::map<Address, Varnode*>& valStore,
                                     Varnode* out, Varnode* value) {
    int size = out->getSize();
    Address addr = out->getAddress();

    if (size == 1) {
        valStore[addr] = value;
        return;
    }

    if (!value->isConstant()) {
        for (int i = 0; i < size; i++) {
            valStore[addr.addWrap(i)] = value;
        }
        return;
    }

    // Split constant into bytes
    int64_t rawValue = value->getOffset();
    for (int i = 0; i < size; i++) {
        int shift = (isBE ? (size - i - 1) : i) * 8;
        int64_t byteVal = (rawValue >> shift) & 0xff;
        Address byteAddr = addr.addWrap(i);
        valStore[byteAddr] = createConstantVarnode(byteVal, 1);
    }
}

// ============================================================================
// Varnode factory methods
// ============================================================================

Varnode* VarnodeContext::createVarnode(int64_t value, int spaceID, int size) {
    if (spaceID == 0) {
        return createConstantVarnode(value, size);
    }
    const AddressSpace* space = addrFactory ? addrFactory->getAddressSpace(spaceID) : nullptr;
    if (space == nullptr) {
        return createConstantVarnode(value, size);
    }
    auto* vn = new Varnode(Address(const_cast<AddressSpace*>(space), value), size);
    allocatedVarnodes.push_back(vn);
    return vn;
}

Varnode* VarnodeContext::createConstantVarnode(int64_t value, int size) {
    if (size == 1) {
        uint8_t b = static_cast<uint8_t>(value);
        const int offset = 128;
        if (byteVarnodes[b + offset] == nullptr) {
            const AddressSpace* constSpace = addrFactory ? addrFactory->getConstantSpace() : nullptr;
            if (constSpace) {
                Address addr(const_cast<AddressSpace*>(constSpace), b & 0xff);
                byteVarnodes[b + offset] = new Varnode(addr, 1);
                allocatedVarnodes.push_back(byteVarnodes[b + offset]);
            }
        }
        if (byteVarnodes[b + offset]) return byteVarnodes[b + offset];
    }
    const AddressSpace* constSpace = addrFactory ? addrFactory->getConstantSpace() : nullptr;
    auto* vn = new Varnode(constSpace ? Address(const_cast<AddressSpace*>(constSpace), value) : Address(), size);
    allocatedVarnodes.push_back(vn);
    return vn;
}

// ============================================================================
// Type checks
// ============================================================================

bool VarnodeContext::isConstant(Varnode* varnode) const {
    if (varnode == nullptr) return false;
    return varnode->isConstant() || isSuspectConstant(varnode);
}

bool VarnodeContext::isSuspectConstant(Varnode* varnode) const {
    if (varnode == nullptr) return false;
    return varnode->getSpace() == SUSPECT_OFFSET_SPACEID;
}

bool VarnodeContext::isRegister(Varnode* varnode) const {
    if (varnode == nullptr) return false;
    if (varnode->isRegister()) return true;
    if (program) {
        Register* reg = program->getRegister(varnode->getAddress());
        return reg != nullptr;
    }
    return false;
}

bool VarnodeContext::isSymbolicSpace(AddressSpace* space) const {
    if (space == nullptr) return false;
    int type = AddressSpace::ID_TYPE_MASK & space->getSpaceID();
    return type == AddressSpace::TYPE_SYMBOL;
}

bool VarnodeContext::isSymbolicSpace(int spaceID) const {
    int type = AddressSpace::ID_TYPE_MASK & spaceID;
    return type == AddressSpace::TYPE_SYMBOL;
}

bool VarnodeContext::readExecutableCode() const { return hitDest; }
void VarnodeContext::setReadExecutableCode() { hitDest = true; }
void VarnodeContext::clearReadExecutableCode() { hitDest = false; }

// ============================================================================
// Register mapping
// ============================================================================

Register* VarnodeContext::getRegister(Varnode* vnode) const {
    if (vnode == nullptr || !program) return nullptr;
    return program->getRegister(vnode->getAddress());
}

Register* VarnodeContext::getRegister(const std::string& name) const {
    if (!program) return nullptr;
    return program->getRegister(name);
}

Register* VarnodeContext::getRegister(const std::string& name) {
    if (!program) return nullptr;
    return program->getRegister(name);
}

Varnode* VarnodeContext::getRegisterVarnode(Register* reg) {
    if (reg == nullptr) return nullptr;
    auto* vn = new Varnode(reg->getAddress(), reg->getMinimumByteSize());
    allocatedVarnodes.push_back(vn);
    return vn;
}

int64_t* VarnodeContext::getConstant(Varnode* vnode, ContextEvaluator* evaluator) {
    if (vnode == nullptr) return nullptr;
    if (!isConstant(vnode)) {
        if (evaluator == nullptr) return nullptr;
        Instruction* instr = getCurrentInstruction(currentAddress);
        return evaluator->unknownValue(this, instr, vnode);
    }
    return new int64_t(vnode->getOffset());
}

Varnode* VarnodeContext::getVarnode(int spaceID, int64_t offset, int size) {
    const AddressSpace* space = addrFactory ? addrFactory->getAddressSpace(spaceID) : nullptr;
    if (space == nullptr) return nullptr;
    auto* vn = new Varnode(Address(const_cast<AddressSpace*>(space), offset), size);
    allocatedVarnodes.push_back(vn);
    return vn;
}

// ============================================================================
// Arithmetic
// ============================================================================

Varnode* VarnodeContext::add(Varnode* val1, Varnode* val2, ContextEvaluator* evaluator) {
    if (val1 == nullptr || val2 == nullptr) return nullptr;

    if (isConstant(val1) || val1->isAddress()) {
        std::swap(val1, val2);
    }

    int spaceID = val1->getSpace();
    int64_t valbase = 0;

    if (isRegister(val1)) {
        if (*val1 == *val2) {
            // adding register to itself - unclear result
        } else {
            Register* reg = getRegister(val1);
            if (reg == nullptr) return nullptr;
            spaceID = getAddressSpace(reg->getName(), reg->getBitLength());
            valbase = 0;
            if (evaluator) {
                Instruction* instr = getCurrentInstruction(currentAddress);
                int64_t* uval = evaluator->unknownValue(this, instr, val1);
                if (uval) {
                    valbase = *uval;
                    spaceID = val2->getSpace();
                    delete uval;
                }
            }
        }
    } else if (isConstant(val1)) {
        valbase = val1->getOffset();
        if (!isSuspectConstant(val1)) spaceID = val2->getSpace();
    } else {
        return nullptr;
    }

    int64_t* val2Const = getConstant(val2, nullptr);
    if (val2Const == nullptr) return nullptr;

    int64_t result = (valbase + *val2Const);
    int shift = (8 - val1->getSize()) * 8;
    if (shift > 0) result = result & (0xffffffffffffffffLL >> shift);
    delete val2Const;
    return createVarnode(result, spaceID, val1->getSize());
}

Varnode* VarnodeContext::subtract(Varnode* val1, Varnode* val2, ContextEvaluator* evaluator) {
    if (val1 == nullptr || val2 == nullptr) return nullptr;
    if (*val1 == *val2) {
        return createConstantVarnode(0, val1->getSize() > 0 ? val1->getSize() : 1);
    }

    int spaceID = val1->getSpace();
    int64_t valbase = 0;

    if (isConstant(val1)) {
        valbase = val1->getOffset();
        if (!isSuspectConstant(val1)) spaceID = val2->getSpace();
    } else if (isRegister(val1)) {
        Register* reg = getRegister(val1);
        if (reg == nullptr) return nullptr;
        spaceID = getAddressSpace(reg->getName(), reg->getBitLength());
        valbase = 0;
    } else {
        return nullptr;
    }

    int64_t* val2Const = getConstant(val2, nullptr);
    if (val2Const == nullptr) return nullptr;
    int64_t result = (valbase - *val2Const);
    int shift = (8 - val1->getSize()) * 8;
    if (shift > 0) result = result & (0xffffffffffffffffLL >> shift);
    delete val2Const;
    return createVarnode(result, spaceID, val1->getSize());
}

Varnode* VarnodeContext::and_(Varnode* val1, Varnode* val2, ContextEvaluator* evaluator) {
    if (val1 == nullptr || val2 == nullptr) return nullptr;
    if (*val1 == *val2) return val1;

    if (isConstant(val1) || val1->isAddress()) {
        std::swap(val1, val2);
    }
    int spaceID = val1->getSpace();
    int64_t valbase = 0;

    if (isRegister(val1)) {
        Register* reg = getRegister(val1);
        if (reg == nullptr) return nullptr;
        spaceID = getAddressSpace(reg->getName(), reg->getBitLength());
        valbase = 0;
    } else if (val1->isConstant()) {
        valbase = val1->getOffset();
        if (!isSuspectConstant(val1)) spaceID = val2->getSpace();
    } else {
        return nullptr;
    }

    int64_t* val2Const = getConstant(val2, nullptr);
    if (val2Const == nullptr) return nullptr;
    int64_t result = (valbase & *val2Const);
    int shift = (8 - val1->getSize()) * 8;
    if (shift > 0) result = result & (0xffffffffffffffffLL >> shift);
    delete val2Const;
    return createVarnode(result, spaceID, val1->getSize());
}

Varnode* VarnodeContext::or_(Varnode* val1, Varnode* val2, ContextEvaluator* evaluator) {
    if (val1 == nullptr || val2 == nullptr) return nullptr;
    if (*val1 == *val2) return val1;

    if (isConstant(val1) || val1->isAddress()) {
        std::swap(val1, val2);
    }
    int spaceID = val1->getSpace();

    int64_t* val2Const = getConstant(val2, nullptr);
    if (val2Const == nullptr) return nullptr;
    if (*val2Const == 0) {
        delete val2Const;
        return val1;
    }

    int64_t* val1Const = getConstant(val1, evaluator);
    if (val1Const == nullptr) { delete val2Const; return nullptr; }

    int64_t lresult = *val1Const | *val2Const;
    delete val1Const;
    delete val2Const;
    return createVarnode(lresult, spaceID, val1->getSize());
}

// ============================================================================
// ProcessorContext interface
// ============================================================================

Register* VarnodeContext::getBaseContextRegister() { return nullptr; }
std::vector<Register*> VarnodeContext::getRegisters() { return {}; }

uint64_t VarnodeContext::getValue(Register* reg, bool isSigned) const {
    Varnode* regVnode = const_cast<VarnodeContext*>(this)->getRegisterVarnode(reg);
    Varnode* value = const_cast<VarnodeContext*>(this)->getValue(regVnode, isSigned, nullptr);
    if (value == nullptr || !isConstant(value)) return 0;
    return value->getOffset();
}

RegisterValue* VarnodeContext::getRegisterValue(Register* reg) const {
    Varnode* regVnode = const_cast<VarnodeContext*>(this)->getRegisterVarnode(reg);
    Varnode* value = const_cast<VarnodeContext*>(this)->getValue(regVnode, false, nullptr);
    if (value != nullptr && isConstant(value)) {
        return new RegisterValue(reg, value->getOffset(), value->getSize());
    }
    return nullptr;
}

bool VarnodeContext::hasValue(Register* reg) const {
    Varnode* regVnode = const_cast<VarnodeContext*>(this)->getRegisterVarnode(reg);
    Varnode* value = const_cast<VarnodeContext*>(this)->getValue(regVnode, false, nullptr);
    return value != nullptr;
}

void VarnodeContext::setValue(Register* reg, uint64_t value) {
    Varnode* regVnode = getRegisterVarnode(reg);
    putValue(regVnode, createConstantVarnode(static_cast<int64_t>(value), regVnode->getSize()), false);
    propogateResults(false);
}

void VarnodeContext::setRegisterValue(RegisterValue* value) {
    if (value) {
        setValue(value->getRegister(), value->getUnsignedOffset());
    }
}

void VarnodeContext::clearRegister(Register* reg) {
    if (reg == nullptr) return;
    std::string spaceName = reg->getName() + "-current";
    int spaceId = getAddressSpace(spaceName, reg->getBitLength());
    Varnode* regVnode = getRegisterVarnode(reg);
    putMemoryValue(regVals, regVnode, createVarnode(0, spaceId, regVnode->getSize()));
}

// ============================================================================
// Branch state management
// ============================================================================

void VarnodeContext::pushMemState(bool saveTempUniques) {
    regValsStack.push(regVals);
    regVals.clear();
    memoryValsStack.push(memoryVals);
    memoryVals.clear();
    uniqueValsStack.push(tempUniqueVals);
    tempUniqueVals.clear();
}

void VarnodeContext::popMemState() {
    if (!regValsStack.empty()) { regVals = regValsStack.top(); regValsStack.pop(); }
    if (!memoryValsStack.empty()) { memoryVals = memoryValsStack.top(); memoryValsStack.pop(); }
    if (!uniqueValsStack.empty()) { tempUniqueVals = uniqueValsStack.top(); uniqueValsStack.pop(); }
    tempVals.clear();
}

// ============================================================================
// Address space management
// ============================================================================

int VarnodeContext::getAddressSpace(const std::string& name, int bitSize) {
    if (addrFactory) {
        const AddressSpace* space = addrFactory->getAddressSpace(name);
        if (space) return space->getSpaceID();
    }
    return BAD_SPACE_ID_VALUE;
}

// ============================================================================
// Register value context queries
// ============================================================================

RegisterValue* VarnodeContext::getRegisterValue(Register* reg, const Address& toAddr) {
    Varnode* rvnode = getRegisterVarnode(reg);
    Varnode* value = getValue(rvnode, false, nullptr);
    if (value == nullptr) return nullptr;
    int spaceID = value->getSpace();
    const AddressSpace* constSpace = addrFactory ? addrFactory->getConstantSpace() : nullptr;
    int constSpaceID = constSpace ? constSpace->getSpaceID() : 0;
    if (spaceID != constSpaceID && spaceID != SUSPECT_OFFSET_SPACEID) return nullptr;
    return new RegisterValue(reg, value->getOffset(), value->getSize());
}

// ============================================================================
// Read-only check
// ============================================================================

bool VarnodeContext::isReadOnly(const Address& addr) {
    if (!program || !program->getMemory()) return false;
    MemoryBlock* block = program->getMemory()->getBlock(addr);
    if (block == nullptr) return false;
    bool readOnly = !block->isWrite();
    return readOnly;
}

// ============================================================================
// Additional arithmetic operations needed by SymbolicPropogator
// ============================================================================

Varnode* VarnodeContext::left(Varnode* val1, Varnode* val2, ContextEvaluator* evaluator) {
    if (val1 == nullptr || val2 == nullptr) return nullptr;
    int64_t* shift = getConstant(val2, evaluator);
    if (shift == nullptr) return nullptr;
    int64_t* base = getConstant(val1, evaluator);
    if (base == nullptr) { delete shift; return nullptr; }
    int64_t result = *base << (*shift & 0x3f);
    int s = 8 * (8 - val1->getSize());
    if (s > 0) result = result & (0xffffffffffffffffLL >> s);
    delete shift; delete base;
    return createConstantVarnode(result, val1->getSize());
}

Varnode* VarnodeContext::right(Varnode* val1, Varnode* val2, ContextEvaluator* evaluator) {
    if (val1 == nullptr || val2 == nullptr) return nullptr;
    int64_t* shift = getConstant(val2, evaluator);
    if (shift == nullptr) return nullptr;
    int64_t* base = getConstant(val1, evaluator);
    if (base == nullptr) { delete shift; return nullptr; }
    int64_t result = static_cast<int64_t>(static_cast<uint64_t>(*base) >> (*shift & 0x3f));
    delete shift; delete base;
    return createConstantVarnode(result, val1->getSize());
}

void VarnodeContext::copy(Varnode* out, Varnode* in, bool mustClear, ContextEvaluator* evaluator) {
    if (out == nullptr || in == nullptr) return;
    Varnode* val = getValue(in, evaluator);
    putValue(out, val, mustClear);
}

Varnode* VarnodeContext::extendValue(Varnode* out, const std::vector<Varnode*>& in, bool sext, ContextEvaluator* evaluator) {
    if (in.empty() || in[0] == nullptr) return nullptr;
    Varnode* val = getValue(in[0], sext, evaluator);
    if (val == nullptr) return nullptr;
    if (isConstant(val)) {
        int64_t v = val->getOffset();
        int outSize = out ? out->getSize() : val->getSize();
        if (outSize > val->getSize()) {
            if (sext && (v & (1LL << (val->getSize() * 8 - 1)))) {
                v |= ~((1LL << (val->getSize() * 8)) - 1);
            } else {
                v &= (1LL << (val->getSize() * 8)) - 1;
            }
        }
        return createConstantVarnode(v, outSize);
    }
    return val;
}

Varnode* VarnodeContext::getVarnode(Varnode* spaceVn, Varnode* offsetVn, int size, ContextEvaluator* evaluator) {
    if (spaceVn == nullptr || offsetVn == nullptr) return nullptr;
    Varnode* resolvedSpace = getValue(spaceVn, evaluator);
    if (resolvedSpace == nullptr) resolvedSpace = spaceVn;
    int spaceID = resolvedSpace->getSpace();
    int64_t* offset = getConstant(offsetVn, evaluator);
    if (offset == nullptr) {
        return getVarnode(spaceID, offsetVn->getOffset(), size);
    }
    Varnode* result = getVarnode(spaceID, *offset, size);
    delete offset;
    return result;
}

bool VarnodeContext::isExternalSpace(int spaceID) const {
    return (AddressSpace::ID_TYPE_MASK & spaceID) == AddressSpace::TYPE_EXTERNAL;
}

bool VarnodeContext::isExternalSpace(AddressSpace* space) const {
    if (space == nullptr) return false;
    return space->isExternalSpace();
}

bool VarnodeContext::isStackSymbolicSpace(Varnode* varnode) const {
    if (varnode == nullptr) return false;
    AddressSpace* space = varnode->getAddress().getAddressSpace();
    if (space == nullptr) return false;
    std::string name = space->getName();
    return name.find("track_") == 0 && validSymbolicStackNames.find(name.substr(6)) != validSymbolicStackNames.end();
}

bool VarnodeContext::isSymbol(Varnode* varnode) const {
    if (varnode == nullptr) return false;
    if (varnode->isAddress()) return true;
    AddressSpace* space = varnode->getAddress().getAddressSpace();
    if (space == nullptr) return false;
    std::string name = space->getName();
    return name.find("track_") == 0;
}

Varnode* VarnodeContext::getStackVarnode() {
    if (stackReg == nullptr) return nullptr;
    if (stackVarnode == nullptr) {
        stackVarnode = getRegisterVarnode(stackReg);
    }
    return stackVarnode;
}

Varnode** VarnodeContext::getReturnVarnode(Function* func) {
    static Varnode* emptyResult[1] = { nullptr };
    static Varnode* p[2] = { nullptr, nullptr };
    p[0] = nullptr; p[1] = nullptr;
    if (func == nullptr || program == nullptr) return emptyResult;
    const std::vector<Variable*>& params = func->getParameters();
    int idx = 0;
    for (Variable* v : params) {
        if (idx >= 1) break;
        // simplified: return varnode not tracked through parameters
        (void)v;
    }
    if (idx == 0) return emptyResult;
    p[idx] = nullptr;
    return p;
}

Varnode** VarnodeContext::getKilledVarnodes(Function* func) {
    static Varnode* emptyResult[1] = { nullptr };
    static Varnode* p[2] = { nullptr, nullptr };
    p[0] = nullptr; p[1] = nullptr;
    if (func == nullptr) return emptyResult;
    Register* stackPtr = nullptr;
    if (program && program->getCompilerSpec()) {
        stackPtr = program->getCompilerSpec()->getStackPointer();
    }
    if (stackPtr) {
        p[0] = getRegisterVarnode(stackPtr);
        p[1] = nullptr;
    }
    return p;
}

std::vector<Address> VarnodeContext::getKnownFlowToAddresses(const Address& addr) const {
    auto it = flowToFromLists.find(addr);
    if (it != flowToFromLists.end()) {
        return it->second;
    }
    return {};
}

Address VarnodeContext::getLastSetLocation(Varnode* vnode, const Address& bval) {
    (void)vnode; (void)bval;
    return Address();
}

Address VarnodeContext::getLastSetLocation(Register* reg, const Address& bval) {
    (void)reg; (void)bval;
    return Address();
}

Varnode* VarnodeContext::getRegisterVarnodeValue(Register* reg, const Address& fromAddr, const Address& toAddr, bool useEndState) {
    (void)fromAddr; (void)toAddr; (void)useEndState;
    if (reg == nullptr) return nullptr;
    Varnode* regVn = getRegisterVarnode(reg);
    return getValue(regVn, nullptr);
}

Varnode* VarnodeContext::getEndRegisterVarnodeValue(Register* reg, const Address& fromAddr, const Address& toAddr, bool useEndState) {
    (void)fromAddr; (void)toAddr; (void)useEndState;
    if (reg == nullptr) return nullptr;
    Varnode* regVn = getRegisterVarnode(reg);
    return getValue(regVn, nullptr);
}

} // namespace ghidra
