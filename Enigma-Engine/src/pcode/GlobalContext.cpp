#include <ghidra/GlobalContext.h>
#include <stdexcept>

namespace ghidra {

GlobalContext::GlobalContext() : allowSet(true) {
}

void GlobalContext::addRegister(const std::string& name, int4 startBit, int4 numBits, uintb defaultValue) {
    ContextRegister reg;
    reg.name = name;
    reg.startBit = startBit;
    reg.numBits = numBits;
    reg.defaultValue = defaultValue;
    reg.currentValue = defaultValue;
    reg.mask = (numBits >= 64) ? ~uintb(0) : (uintb(1) << numBits) - 1;
    registers[name] = reg;
}

void GlobalContext::setDefaultValue(const std::string& name, uintb value) {
    auto it = registers.find(name);
    if (it == registers.end()) {
        throw std::runtime_error("Unknown context register: " + name);
    }
    it->second.defaultValue = value & it->second.mask;
    it->second.currentValue = it->second.defaultValue;
}

uintb GlobalContext::getDefaultValue(const std::string& name) const {
    auto it = registers.find(name);
    if (it == registers.end()) return 0;
    return it->second.defaultValue;
}

void GlobalContext::setCurrentAddress(const Address& addr) {
    currentAddr = addr;
}

void GlobalContext::setContext(const Address& startAddr, const Address& endAddr, const std::string& name, uintb value) {
    if (!allowSet) return;

    auto it = registers.find(name);
    if (it == registers.end()) {
        throw std::runtime_error("Unknown context register: " + name);
    }

    ContextChange change;
    change.startAddr = startAddr;
    change.endAddr = endAddr;
    change.registerName = name;
    change.value = value & it->second.mask;
    changes.push_back(change);
}

uintb GlobalContext::getContext(const Address& addr, const std::string& name) const {
    auto it = registers.find(name);
    if (it == registers.end()) return 0;

    for (auto rit = changes.rbegin(); rit != changes.rend(); ++rit) {
        if (rit->registerName == name && addr >= rit->startAddr && addr <= rit->endAddr) {
            return rit->value;
        }
    }

    return it->second.defaultValue;
}

uintb GlobalContext::getContext(const std::string& name) const {
    return getContext(currentAddr, name);
}

bool GlobalContext::hasRegister(const std::string& name) const {
    return registers.find(name) != registers.end();
}

int4 GlobalContext::getRegisterSize(const std::string& name) const {
    auto it = registers.find(name);
    return (it != registers.end()) ? it->second.numBits : 0;
}

int4 GlobalContext::getRegisterStartBit(const std::string& name) const {
    auto it = registers.find(name);
    return (it != registers.end()) ? it->second.startBit : 0;
}

void GlobalContext::clear() {
    registers.clear();
    changes.clear();
}

void GlobalContext::clearChanges() {
    changes.clear();
}

void GlobalContext::resetToDefaults() {
    for (auto& pair : registers) {
        pair.second.currentValue = pair.second.defaultValue;
    }
}

} // namespace ghidra
