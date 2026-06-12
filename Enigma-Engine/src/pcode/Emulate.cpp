#include <ghidra/Emulate.h>
#include <ghidra/PcodeOp.h>
#include <iostream>
#include <algorithm>
#include <stdexcept>

namespace ghidra {

// ============================================================================
// EmulateCallback
// ============================================================================

EmulateCallback::EmulateCallback() : emulate(nullptr) {}

void EmulateCallback::setEmulate(Emulate* emu) {
    emulate = emu;
}

bool EmulateCallback::pcodeCallback(PcodeOp* op) {
    return true;
}

bool EmulateCallback::addressCallback(const Address& addr) {
    return true;
}

// ============================================================================
// BreakTable
// ============================================================================

void BreakTable::setEmulate(Emulate* emu) {
    for (auto const& [id, cb] : pcodeCallbacks) cb->setEmulate(emu);
    for (auto const& [addr, cb] : addressCallbacks) cb->setEmulate(emu);
}

bool BreakTable::doPcodeOpBreak(PcodeOp* op) {
    uint32_t opId = static_cast<uint32_t>(op->getOpcode());
    auto it = pcodeCallbacks.find(opId);
    if (it != pcodeCallbacks.end()) {
        return it->second->pcodeCallback(op);
    }
    return false;
}

bool BreakTable::doAddressBreak(const Address& addr) {
    auto it = addressCallbacks.find(addr);
    if (it != addressCallbacks.end()) {
        return it->second->addressCallback(addr);
    }
    return false;
}

void BreakTable::registerPcodeCallback(uint32_t opIndex, EmulateCallback* cb) {
    pcodeCallbacks[opIndex] = cb;
}

void BreakTable::registerAddressCallback(const Address& addr, EmulateCallback* cb) {
    addressCallbacks[addr] = cb;
}

// ============================================================================
// Emulate
// ============================================================================

Emulate::Emulate() : emuHalted(true), currentOpcode(0) {}

void Emulate::setHalt(bool val) {
    emuHalted = val;
}

bool Emulate::getHalt() const {
    return emuHalted;
}

void Emulate::executeCurrentOp() {
    if (emuHalted) return;

    switch (currentOpcode) {
        case PcodeOp::COPY: executeUnary(); break;
        case PcodeOp::INT_ADD:
        case PcodeOp::INT_SUB:
        case PcodeOp::INT_XOR:
        case PcodeOp::INT_AND:
        case PcodeOp::INT_OR:
            executeBinary(); 
            break;
        case PcodeOp::LOAD: executeLoad(); break;
        case PcodeOp::STORE: executeStore(); break;
        case PcodeOp::BRANCH: executeBranch(); break;
        case PcodeOp::CBRANCH: {
            if (executeCbranch()) {
                executeBranch();
            } else {
                fallthruOp();
            }
            break;
        }
        case PcodeOp::BRANCHIND: executeBranchind(); break;
        case PcodeOp::CALL: executeCall(); break;
        case PcodeOp::CALLIND: executeCallind(); break;
        case PcodeOp::CALLOTHER: executeCallother(); break;
        case PcodeOp::RETURN: executeBranch(); break; // Return is similar to branch in base emu
        case PcodeOp::MULTIEQUAL: executeMultiequal(); break;
        case PcodeOp::INDIRECT: executeIndirect(); break;
        case PcodeOp::SEGMENTOP: executeSegmentOp(); break;
        case PcodeOp::CPOOLREF: executeCpoolRef(); break;
        case PcodeOp::NEW: executeNew(); break;
        default:
            // Non-implemented opcode
            break;
    }
}

// ============================================================================
// MemoryState
// ============================================================================

MemoryState::MemoryState(bool be) : bigEndian(be) {}

void MemoryState::registerBank(const std::string& name, uint64_t base, size_t size, bool readOnly) {
    banks[name] = MemoryBank(base, size, readOnly);
}

void MemoryState::setRegister(const std::string& name, uint64_t value) {
    registers[name] = value;
}

uint64_t MemoryState::getRegister(const std::string& name) const {
    auto it = registers.find(name);
    return (it != registers.end()) ? it->second : 0;
}

bool MemoryState::hasRegister(const std::string& name) const {
    return registers.find(name) != registers.end();
}

void MemoryState::writeMemory(uint64_t addr, const uint8_t* data, size_t size) {
    for (auto& pair : banks) {
        MemoryBank& bank = pair.second;
        if (addr >= bank.baseOffset && addr + size <= bank.baseOffset + bank.data.size()) {
            if (bank.readOnly) throw std::runtime_error("Write to read-only memory bank");
            std::copy(data, data + size, bank.data.begin() + (addr - bank.baseOffset));
            return;
        }
    }
    throw std::runtime_error("Memory write out of bounds");
}

void MemoryState::readMemory(uint64_t addr, uint8_t* out, size_t size) const {
    for (const auto& pair : banks) {
        const MemoryBank& bank = pair.second;
        if (addr >= bank.baseOffset && addr + size <= bank.baseOffset + bank.data.size()) {
            std::copy(bank.data.begin() + (addr - bank.baseOffset), 
                      bank.data.begin() + (addr - bank.baseOffset) + size, out);
            return;
        }
    }
    throw std::runtime_error("Memory read out of bounds");
}

uint64_t MemoryState::readValue(uint64_t addr, size_t size) const {
    uint8_t buf[8] = {0};
    readMemory(addr, buf, size);
    uint64_t val = 0;
    if (bigEndian) {
        for (size_t i = 0; i < size; ++i) val = (val << 8) | buf[i];
    } else {
        for (size_t i = 0; i < size; ++i) val |= (uint64_t)buf[i] << (i * 8);
    }
    return val;
}

void MemoryState::writeValue(uint64_t addr, uint64_t value, size_t size) {
    uint8_t buf[8] = {0};
    if (bigEndian) {
        for (int i = (int)size - 1; i >= 0; --i) {
            buf[i] = value & 0xFF;
            value >>= 8;
        }
    } else {
        for (size_t i = 0; i < size; ++i) {
            buf[i] = value & 0xFF;
            value >>= 8;
        }
    }
    writeMemory(addr, buf, size);
}

uint64_t MemoryState::readValue(const std::string& regName, size_t size) const {
    uint64_t val = getRegister(regName);
    return val & ((1ULL << size * 8) - 1); // Simplified masking
}

void MemoryState::writeValue(const std::string& regName, uint64_t value, size_t size) {
    setRegister(regName, value);
}

// ============================================================================
// EmulateMemory
// ============================================================================

EmulateMemory::EmulateMemory(MemoryState* mem) : memState(mem), currentOp(nullptr) {}

void EmulateMemory::executeUnary() {
    if (!currentOp || !memState) return;
    Varnode* in = currentOp->getInput(0);
    Varnode* out = currentOp->getOutput();
    if (!in || !out) return;
    uint64_t val = 0;
    if (in->isConstant())
        val = static_cast<uint64_t>(in->getOffset());
    else if (in->isRegister())
        val = memState->getRegister(in->getAddress().getAddressSpace()->getName());
    memState->writeValue(out->getAddress().getAddressSpace()->getName(), val, out->getSize());
}

void EmulateMemory::executeBinary() {
    if (!currentOp || !memState) return;
    if (currentOp->getNumInputs() < 2) return;
    Varnode* in0 = currentOp->getInput(0);
    Varnode* in1 = currentOp->getInput(1);
    Varnode* out = currentOp->getOutput();
    if (!in0 || !in1 || !out) return;
    uint64_t a = (in0->isConstant()) ? static_cast<uint64_t>(in0->getOffset()) : memState->getRegister(in0->getAddress().getAddressSpace()->getName());
    uint64_t b = (in1->isConstant()) ? static_cast<uint64_t>(in1->getOffset()) : memState->getRegister(in1->getAddress().getAddressSpace()->getName());
    uint64_t result = 0;
    switch (currentOpcode) {
        case PcodeOp::INT_ADD: result = a + b; break;
        case PcodeOp::INT_SUB: result = a - b; break;
        case PcodeOp::INT_XOR: result = a ^ b; break;
        case PcodeOp::INT_AND: result = a & b; break;
        case PcodeOp::INT_OR:  result = a | b; break;
        default: return;
    }
    memState->writeValue(out->getAddress().getAddressSpace()->getName(), result, out->getSize());
}

void EmulateMemory::executeLoad() {
    if (!currentOp || !memState) return;
    if (currentOp->getNumInputs() < 1) return;
    Varnode* addrVn = currentOp->getInput(0);
    Varnode* out = currentOp->getOutput();
    if (!addrVn || !out) return;
    uint64_t loadAddr = static_cast<uint64_t>(addrVn->getOffset());
    uint64_t val = memState->readValue(loadAddr, out->getSize());
    memState->writeValue(out->getAddress().getAddressSpace()->getName(), val, out->getSize());
}

void EmulateMemory::executeStore() {
    if (!currentOp || !memState) return;
    if (currentOp->getNumInputs() < 2) return;
    Varnode* addrVn = currentOp->getInput(0);
    Varnode* valVn = currentOp->getInput(1);
    if (!addrVn || !valVn) return;
    uint64_t storeAddr = static_cast<uint64_t>(addrVn->getOffset());
    uint64_t val = (valVn->isConstant()) ? static_cast<uint64_t>(valVn->getOffset()) : memState->getRegister(valVn->getAddress().getAddressSpace()->getName());
    memState->writeValue(storeAddr, val, valVn->getSize());
}

void EmulateMemory::executeBranch() {
    // Overridden in EmulatePcodeCache with address resolution
}

bool EmulateMemory::executeCbranch() {
    // Overridden in EmulatePcodeCache with condition evaluation
    return true;
}

void EmulateMemory::executeBranchind() {
    // Overridden in EmulatePcodeCache with address resolution
}

void EmulateMemory::executeCall() {
    // Subclasses override with call semantics
}

void EmulateMemory::executeCallind() {
    // Subclasses override with indirect call semantics
}

void EmulateMemory::executeCallother() {
    // Subclasses override with CALLOTHER pcode semantics
}

void EmulateMemory::executeMultiequal() {
    // PHI node — value comes from the reaching definition
}

void EmulateMemory::executeIndirect() {
    // INDIRECT marker — no execution needed
}

void EmulateMemory::executeSegmentOp() {
    // SEGMENTOP — not implemented in base
}

void EmulateMemory::executeCpoolRef() {
    // CPOOLREF — not implemented in base
}

void EmulateMemory::executeNew() {
    // NEW — not implemented in base
}

// ============================================================================
// EmulatePcodeCache
// ============================================================================

EmulatePcodeCache::EmulatePcodeCache(Translate* t, MemoryState* s, BreakTable* b)
    : EmulateMemory(s), translator(t), currentAddress(Address::NO_ADDRESS), 
      instructionStart(true), currentOpIndex(0), instructionLength(0) {
    breakTable = b;
}


EmulatePcodeCache::~EmulatePcodeCache() {
}

void EmulatePcodeCache::clearCache() {
    opCache.clear();
    varCache.clear();
}

void EmulatePcodeCache::createInstruction(const Address& addr) {
    clearCache();
    currentFD_ = std::make_unique<Funcdata>("", addr);
    int length = translator->oneInstruction(*currentFD_, addr);
    instructionLength = length;
    for (int i = 0; i < currentFD_->getNumOps(); ++i) {
        opCache.push_back(currentFD_->getOp(i));
    }
    for (int i = 0; i < currentFD_->getNumVarnodes(); ++i) {
        varCache.push_back(currentFD_->getVarnode(i));
    }
}

void EmulatePcodeCache::establishOp() {
    if (currentOpIndex < (int)opCache.size()) {
        currentOp = opCache[currentOpIndex];
        currentOpcode = currentOp->getOpcode();
    } else {
        emuHalted = true;
    }
}

void EmulatePcodeCache::executeInstruction() {
    while (currentOpIndex < (int)opCache.size()) {
        establishOp();
        executeCurrentOp();
        currentOpIndex++;
    }
    instructionStart = true;
}

void EmulatePcodeCache::setExecuteAddress(const Address& addr) {
    currentAddress = addr;
    instructionStart = true;
    currentOpIndex = 0;
    createInstruction(addr);
}

Address EmulatePcodeCache::getExecuteAddress() const {
    return currentAddress;
}

PcodeOp* EmulatePcodeCache::getOpByIndex(int i) const {
    if (i < 0 || i >= (int)opCache.size()) return nullptr;
    return opCache[i];
}


void EmulatePcodeCache::fallthruOp() {
    currentOpIndex = (int)opCache.size();
    if (instructionLength > 0) {
        Address nextAddr = currentAddress.add(instructionLength);
        setExecuteAddress(nextAddr);
    }
}

void EmulatePcodeCache::executeBranch() {
    if (currentOp && currentOp->getNumInputs() > 0) {
        Varnode* target = currentOp->getInput(currentOp->getNumInputs() - 1);
        AddressSpace* space = const_cast<AddressSpace*>(target->getAddress().getAddressSpace());
        int64_t targetOff = target->getOffset();
        currentAddress = Address(space, targetOff);
    }
    currentOpIndex = (int)opCache.size();
    instructionStart = true;
}

bool EmulatePcodeCache::executeCbranch() {
    if (!currentOp || currentOp->getNumInputs() < 2) return false;
    Varnode* cond = currentOp->getInput(0);
    if (!cond) return false;
    uint64_t condVal = 0;
    if (cond->isConstant()) {
        condVal = static_cast<uint64_t>(cond->getOffset());
    } else if (memState) {
        condVal = memState->getRegister(cond->getAddress().getAddressSpace()->getName());
    }
    return condVal != 0;
}

void EmulatePcodeCache::executeCallother() {
    if (breakTable && currentOp) {
        breakTable->doPcodeOpBreak(currentOp);
    }
}

} // namespace ghidra
