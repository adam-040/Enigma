#include "ghidra/SleighLanguage.h"
#include "ghidra/ProgramAddressFactory.h"
#include "ghidra/Register.h"
#include "ghidra/RegisterBuilder.h"
#include "ghidra/AddressSpace.h"
#include "ghidra/MemoryBlockDefinition.h"
#include "ghidra/DefaultProgramContext.h"
#include "ghidra/SleighInstructionPrototype.h"
#include "ghidra/XmlPullParser.h"
#include "ghidra/Decoder.h"
#include "ghidra/ContextField.h"
#include "ghidra/ContextSymbol.h"
#include "ghidra/AddressSet.h"
#include "ghidra/Types.h"

namespace ghidra {

SleighLanguage::SleighLanguage(SleighLanguageDescription* description)
    : description(description) {
    initialize(false, nullptr);
}

SleighLanguage::SleighLanguage(SleighLanguageDescription* description, TaskMonitor* monitor)
    : description(description) {
    initialize(false, monitor);
}

std::string SleighLanguage::toString() const {
    return description ? description->getDescription() : "SleighLanguage";
}

void SleighLanguage::applyContextSettings(DefaultProgramContext* programContext) {
    if (!programContext) return;
    Register* ctxReg = getContextBaseRegister();
    if (ctxReg) {
    }
}

Register* SleighLanguage::getContextBaseRegister() {
    for (auto& pair : registerMap_) {
        if (pair.second->isProcessorContext()) {
            return pair.second;
        }
    }
    return getProgramCounter();
}

std::vector<Register*> SleighLanguage::getContextRegisters() {
    std::vector<Register*> result;
    for (auto& pair : registerMap_) {
        if (pair.second->isProcessorContext()) {
            result.push_back(pair.second);
        }
    }
    return result;
}

std::vector<MemoryBlockDefinition*> SleighLanguage::getDefaultMemoryBlocks() {
    std::vector<MemoryBlockDefinition*> result;
    if (ram_) {
        int memSize = description ? (1 << (description->getSize() - 3)) : 0x100000;
        std::string addrStr = "ram:0x0";
        auto* def = new MemoryBlockDefinition(ram_->getName(), addrStr, memSize,
                                              true, false, true, true, true, false);
        result.push_back(def);
    }
    return result;
}

std::string SleighLanguage::getUserDefinedOpName(int index) {
    if (index >= 0 && index < static_cast<int>(userOps_.size())) {
        return userOps_[index].getName();
    }
    return "";
}

int SleighLanguage::getNumberOfUserDefinedOpNames() {
    return static_cast<int>(userOps_.size());
}

Register* SleighLanguage::getRegister(AddressSpace* addrspc, long offset, int size) {
    if (!addrspc) return nullptr;
    for (auto& pair : registerMap_) {
        Register* reg = pair.second;
        if (reg->getAddressSpace() == addrspc &&
            reg->getOffset() == offset &&
            reg->getNumBytes() >= size) {
            return reg;
        }
    }
    // Try parent register match
    for (auto& pair : registerMap_) {
        Register* reg = pair.second;
        if (reg->getAddressSpace() == addrspc &&
            offset >= reg->getOffset() &&
            offset + size <= reg->getOffset() + reg->getNumBytes()) {
            return reg;
        }
    }
    return nullptr;
}

Register* SleighLanguage::getRegister(const std::string& name) {
    auto it = registerMap_.find(name);
    if (it != registerMap_.end()) {
        return it->second;
    }
    // Check aliases
    for (auto& pair : registerMap_) {
        auto& aliases = pair.second->getAliases();
        if (aliases.find(name) != aliases.end()) {
            return pair.second;
        }
    }
    return nullptr;
}

Register* SleighLanguage::getRegister(Address addr, int size) {
    return getRegister(addr.getAddressSpace(), addr.getOffset(), size);
}

std::vector<Register*> SleighLanguage::getRegisters(Address address) {
    std::vector<Register*> result;
    for (auto& pair : registerMap_) {
        if (pair.second->getAddress() == address) {
            result.push_back(pair.second);
        }
    }
    return result;
}

std::vector<Register*> SleighLanguage::getRegisters() {
    std::vector<Register*> result;
    result.reserve(registerMap_.size());
    for (auto& pair : registerMap_) {
        result.push_back(pair.second);
    }
    return result;
}

std::vector<std::string> SleighLanguage::getRegisterNames() {
    std::vector<std::string> result;
    result.reserve(registerMap_.size());
    for (auto& pair : registerMap_) {
        result.push_back(pair.first);
    }
    return result;
}

InstructionPrototype* SleighLanguage::parse(MemBuffer* buf, ProcessorContext* context, bool inDelaySlot) {
    // Real SLEIGH parsing requires compiled .sla spec files
    // This path is only used when no upstream SLEIGH engine is available
    // Return nullptr to signal that the caller should use the upstream SleighArchitecture
    return nullptr;
}

void SleighLanguage::reloadLanguage(TaskMonitor* monitor) {
    initialize(true, monitor);
}

void SleighLanguage::initialize(bool forceCompile, TaskMonitor* monitor) {
    registerMap_.clear();
    userOps_.clear();
    regOwnedStorage_.clear();
    addrFactory_ = nullptr;
    ram_ = nullptr;
    regAddrSpace_ = nullptr;
    constAddrSpace_ = nullptr;
    uniqueAddrSpace_ = nullptr;
    stackAddrSpace_ = nullptr;
    default_space = nullptr;
    defaultDataSpace = nullptr;
    programCounter = nullptr;

    buildAddressSpaceFactory();
    readInitialDescription();
    _numSections = 1;
}

void SleighLanguage::readInitialDescription() {
    if (!description) return;
    alignment = (description->getSize() == 32) ? 1 : 1;
    uniqueBase = 0x1000;
    uniqueAllocateMask = 0xFF;
    std::string procName = description->getProcessor().getName();
    if (procName == "x86_64" || procName == "x86") {
        buildX86Registers();
    } else if (procName == "ARM" || procName == "AARCH64" || procName == "arm" || procName == "aarch64") {
        buildARMRegisters();
    }
}

void SleighLanguage::buildX86Registers() {
    bool is64 = (description && description->getProcessor().getName() == "x86_64");
    int ptrSize = is64 ? 8 : 4;

    auto addReg = [&](const std::string& name, int size, uint64_t offset, int typeFlags) {
        Address addr(regAddrSpace_, static_cast<int64_t>(offset));
        auto reg = std::make_unique<Register>(name, name, addr, size,
                                              description->getEndian() == Endian::BIG, typeFlags);
        registerMap_[name] = reg.get();
        regOwnedStorage_.push_back(std::move(reg));
    };

    if (is64) {
        addReg("rax", 8, 0, Register::TYPE_NONE);
        addReg("rbx", 8, 1, Register::TYPE_NONE);
        addReg("rcx", 8, 2, Register::TYPE_NONE);
        addReg("rdx", 8, 3, Register::TYPE_NONE);
        addReg("rsp", 8, 4, Register::TYPE_SP);
        addReg("rbp", 8, 5, Register::TYPE_FP);
        addReg("rsi", 8, 6, Register::TYPE_NONE);
        addReg("rdi", 8, 7, Register::TYPE_NONE);
        addReg("r8", 8, 8, Register::TYPE_NONE);
        addReg("r9", 8, 9, Register::TYPE_NONE);
        addReg("r10", 8, 10, Register::TYPE_NONE);
        addReg("r11", 8, 11, Register::TYPE_NONE);
        addReg("r12", 8, 12, Register::TYPE_NONE);
        addReg("r13", 8, 13, Register::TYPE_NONE);
        addReg("r14", 8, 14, Register::TYPE_NONE);
        addReg("r15", 8, 15, Register::TYPE_NONE);
        addReg("rip", 8, 16, Register::TYPE_PC);
        addReg("flags", 8, 100, Register::TYPE_NONE);
        addReg("eflags", 8, 100, Register::TYPE_NONE);
        addReg("rflags", 8, 100, Register::TYPE_NONE);

        addReg("eax", 4, 0, Register::TYPE_NONE);
        addReg("ebx", 4, 1, Register::TYPE_NONE);
        addReg("ecx", 4, 2, Register::TYPE_NONE);
        addReg("edx", 4, 3, Register::TYPE_NONE);
        addReg("esp", 4, 4, Register::TYPE_SP);
        addReg("ebp", 4, 5, Register::TYPE_FP);
        addReg("esi", 4, 6, Register::TYPE_NONE);
        addReg("edi", 4, 7, Register::TYPE_NONE);
        addReg("eip", 4, 16, Register::TYPE_PC);

        addReg("ax", 2, 0, Register::TYPE_NONE);
        addReg("bx", 2, 1, Register::TYPE_NONE);
        addReg("cx", 2, 2, Register::TYPE_NONE);
        addReg("dx", 2, 3, Register::TYPE_NONE);
        addReg("si", 2, 6, Register::TYPE_NONE);
        addReg("di", 2, 7, Register::TYPE_NONE);
        addReg("sp", 2, 4, Register::TYPE_SP);
        addReg("bp", 2, 5, Register::TYPE_FP);

        addReg("al", 1, 0, Register::TYPE_NONE);
        addReg("bl", 1, 1, Register::TYPE_NONE);
        addReg("cl", 1, 2, Register::TYPE_NONE);
        addReg("dl", 1, 3, Register::TYPE_NONE);
        addReg("ah", 1, 0 + 4, Register::TYPE_NONE);
        addReg("bh", 1, 1 + 4, Register::TYPE_NONE);
        addReg("ch", 1, 2 + 4, Register::TYPE_NONE);
        addReg("dh", 1, 3 + 4, Register::TYPE_NONE);

        addReg("spl", 1, 4, Register::TYPE_NONE);
        addReg("bpl", 1, 5, Register::TYPE_NONE);
        addReg("sil", 1, 6, Register::TYPE_NONE);
        addReg("dil", 1, 7, Register::TYPE_NONE);
        programCounter = registerMap_["rip"];
    } else {
        addReg("eax", 4, 0, Register::TYPE_NONE);
        addReg("ebx", 4, 1, Register::TYPE_NONE);
        addReg("ecx", 4, 2, Register::TYPE_NONE);
        addReg("edx", 4, 3, Register::TYPE_NONE);
        addReg("esp", 4, 4, Register::TYPE_SP);
        addReg("ebp", 4, 5, Register::TYPE_FP);
        addReg("esi", 4, 6, Register::TYPE_NONE);
        addReg("edi", 4, 7, Register::TYPE_NONE);
        addReg("eip", 4, 8, Register::TYPE_PC);

        addReg("ax", 2, 0, Register::TYPE_NONE);
        addReg("bx", 2, 1, Register::TYPE_NONE);
        addReg("cx", 2, 2, Register::TYPE_NONE);
        addReg("dx", 2, 3, Register::TYPE_NONE);
        addReg("si", 2, 6, Register::TYPE_NONE);
        addReg("di", 2, 7, Register::TYPE_NONE);
        addReg("sp", 2, 4, Register::TYPE_SP);
        addReg("bp", 2, 5, Register::TYPE_FP);

        addReg("al", 1, 0, Register::TYPE_NONE);
        addReg("bl", 1, 1, Register::TYPE_NONE);
        addReg("cl", 1, 2, Register::TYPE_NONE);
        addReg("dl", 1, 3, Register::TYPE_NONE);
        addReg("ah", 1, 0 + 4, Register::TYPE_NONE);
        addReg("bh", 1, 1 + 4, Register::TYPE_NONE);
        addReg("ch", 1, 2 + 4, Register::TYPE_NONE);
        addReg("dh", 1, 3 + 4, Register::TYPE_NONE);
        programCounter = registerMap_["eip"];
    }
}

void SleighLanguage::buildARMRegisters() {
    auto addReg = [&](const std::string& name, uint64_t offset, int typeFlags) {
        Address addr(regAddrSpace_, static_cast<int64_t>(offset));
        auto reg = std::make_unique<Register>(name, name, addr, 4,
                                              description->getEndian() == Endian::BIG, typeFlags);
        registerMap_[name] = reg.get();
        regOwnedStorage_.push_back(std::move(reg));
    };

    for (int i = 0; i <= 15; i++) {
        std::string name = "r" + std::to_string(i);
        int flags = Register::TYPE_NONE;
        if (i == 13) flags |= Register::TYPE_SP;
        if (i == 14) flags |= Register::TYPE_NONE; // lr
        if (i == 15) flags |= Register::TYPE_PC;
        addReg(name, i, flags);
    }
    addReg("sp", 13, Register::TYPE_SP);
    addReg("lr", 14, Register::TYPE_NONE);
    addReg("pc", 15, Register::TYPE_PC);
    programCounter = registerMap_["pc"];
}

void SleighLanguage::read(XmlPullParser* parser) {
}

void SleighLanguage::readRemainingSpecification() {
}

void SleighLanguage::decode(Decoder* decoder) {
}

void SleighLanguage::parseSpaces(Decoder* decoder) {
}

void SleighLanguage::buildAddressSpaceFactory() {
    addrFactory_ = std::make_unique<ProgramAddressFactory>();

    int size = description ? description->getSize() : 32;
    int ptrSize = (size == 64) ? 8 : 4;

    ram_ = new GenericAddressSpace("ram", size, AddressSpace::TYPE_RAM, ptrSize);
    regAddrSpace_ = new GenericAddressSpace("register", size, AddressSpace::TYPE_REGISTER, ptrSize);
    constAddrSpace_ = new GenericAddressSpace("const", size, AddressSpace::TYPE_CONSTANT, 0);
    uniqueAddrSpace_ = new GenericAddressSpace("unique", 64, AddressSpace::TYPE_UNIQUE, ptrSize);
    stackAddrSpace_ = new GenericAddressSpace("stack", size, AddressSpace::TYPE_STACK, ptrSize);

    addrFactory_->addAddressSpace(ram_);
    addrFactory_->addAddressSpace(regAddrSpace_);
    addrFactory_->addAddressSpace(constAddrSpace_);
    addrFactory_->addAddressSpace(uniqueAddrSpace_);
    addrFactory_->addAddressSpace(stackAddrSpace_);
    addrFactory_->setDefaultSpace(ram_);
    addrFactory_->setConstantSpace(constAddrSpace_);
    addrFactory_->setUniqueSpace(uniqueAddrSpace_);
    addrFactory_->setStackSpace(stackAddrSpace_);
    addrFactory_->setRegisterSpace(regAddrSpace_);

    default_space = ram_;
    defaultDataSpace = ram_;
}

void SleighLanguage::loadRegisters(RegisterBuilder* builder) {
    if (!builder) return;
    auto regs = builder->getRegisters();
    for (const auto& reg : regs) {
        auto* existing = builder->getRegister(reg.getName());
        if (existing) {
            registerMap_[reg.getName()] = existing;
        }
        if (reg.isProgramCounter()) {
            programCounter = registerMap_[reg.getName()];
        }
    }
}

void SleighLanguage::setHasMappedRegisters(AddressSpace* space) {
    if (space) {
        hasMappedRegisters_ = true;
    }
}

void SleighLanguage::registerContext(const std::string& name, ContextField* field, RegisterBuilder* builder) {
    if (!field || !builder) return;
    contextFields_.push_back(field);
}

void SleighLanguage::registerContext(ContextSymbol* sym, RegisterBuilder* builder) {
    if (!sym || !builder) return;
    contextSymbols_.push_back(sym);
}

void SleighLanguage::xrefRegisters() {
    for (auto& pair : registerMap_) {
        Register* reg = pair.second;
        if (reg->hasChildren()) continue;
        if (!reg->getParentRegister()) continue;
        if (reg->getLeastSignificantBit() != 0 || reg->getBitLength() != reg->getNumBytes() * 8) {
        }
    }
}

} // namespace ghidra
