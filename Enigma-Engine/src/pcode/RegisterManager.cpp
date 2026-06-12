#include <ghidra/RegisterManager.h>
#include <algorithm>

namespace ghidra {

RegisterManager::RegisterManager(const std::vector<Register*>& registers,
                                 const std::unordered_map<std::string, Register*>& registerNameMap)
    : registers_(registers),
      registerNameMap_(registerNameMap),
      registerAddressesView_(registerAddresses_) {
    initialize();
}

void RegisterManager::initialize() {
    for (auto* reg : registers_) {
        auto name = reg->getName();
        registerNames_.push_back(name);

        if (reg->isProcessorContext()) {
            contextRegisters_.push_back(reg);
            if (reg->isBaseRegister() && contextBaseRegister_ == nullptr) {
                contextBaseRegister_ = reg;
            }
        }

        auto addr = reg->getAddress();
        registerAddressMap_[addr].push_back(reg);
        addRegisterAddresses(reg);
    }

    for (auto* reg : registers_) {
        if (reg->isBigEndian()) {
            populateSizeMapBigEndian(reg);
        } else {
            populateSizeMapLittleEndian(reg);
        }
    }
}

void RegisterManager::addRegisterAddresses(Register* reg) {
    auto baseAddr = reg->getBaseRegister()->getAddress();
    int numBytes = reg->getMinimumByteSize();
    for (int i = 0; i < numBytes; ++i) {
        Address addr(baseAddr.getAddressSpace(), baseAddr.getOffset() + i);
        registerAddresses_.addRange(addr, addr);
    }
}

void RegisterManager::populateSizeMapBigEndian(Register* reg) {
    auto addr = reg->getAddress();
    int size = reg->getMinimumByteSize();
    auto key = RegisterSizeKey{addr, size};
    auto it = sizeMap_.find(key);
    if (it == sizeMap_.end()) {
        sizeMap_[key] = reg;
    } else if (reg->getParentRegister() == nullptr) {
        sizeMap_[key] = reg;
    }
}

void RegisterManager::populateSizeMapLittleEndian(Register* reg) {
    auto addr = reg->getAddress();
    int size = reg->getMinimumByteSize();
    auto key = RegisterSizeKey{addr, size};
    auto it = sizeMap_.find(key);
    if (it == sizeMap_.end()) {
        sizeMap_[key] = reg;
    } else {
        auto oldSize = it->first.size;
        if (size > oldSize) {
            sizeMap_[key] = reg;
        } else if (size == oldSize && it->second->getParentRegister() != nullptr) {
            sizeMap_[key] = reg;
        }
    }
}

Register* RegisterManager::getRegister(Address addr) {
    auto it = registerAddressMap_.find(addr);
    if (it != registerAddressMap_.end()) {
        auto& list = it->second;
        if (!list.empty()) return list[0];
    }
    return nullptr;
}

Register* RegisterManager::getRegister(Address addr, int size) {
    if (size == 0) return getRegister(addr);
    auto key = RegisterSizeKey{addr, size};
    auto it = sizeMap_.find(key);
    if (it != sizeMap_.end()) return it->second;
    return nullptr;
}

Register* RegisterManager::getRegister(const std::string& name) {
    auto it = registerNameMap_.find(name);
    if (it != registerNameMap_.end()) return it->second;
    return nullptr;
}

std::vector<Register*> RegisterManager::getRegisters(Address addr) {
    auto it = registerAddressMap_.find(addr);
    if (it != registerAddressMap_.end()) return it->second;
    return {};
}

const std::vector<Register*>& RegisterManager::getSortedVectorRegisters() {
    if (!sortedVectorRegistersValid_) {
        sortedVectorRegisters_ = registers_;
        std::sort(sortedVectorRegisters_.begin(), sortedVectorRegisters_.end(), compareVectorRegisters);
        sortedVectorRegistersValid_ = true;
    }
    return sortedVectorRegisters_;
}

bool RegisterManager::compareVectorRegisters(Register* reg1, Register* reg2) {
    int cmp = reg1->getName().compare(reg2->getName());
    if (cmp != 0) return cmp < 0;
    if (reg1->getMinimumByteSize() != reg2->getMinimumByteSize()) {
        return reg1->getMinimumByteSize() < reg2->getMinimumByteSize();
    }
    return false;
}

} // namespace ghidra
