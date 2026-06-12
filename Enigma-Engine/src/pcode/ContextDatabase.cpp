#include <ghidra/ContextDatabase.h>
#include <stdexcept>

namespace ghidra {

void ContextDatabase::addContext(const std::string& name, int4 startBit, int4 numBits) {
    ContextEntry entry;
    entry.name = name;
    entry.startBit = startBit;
    entry.numBits = numBits;
    entry.mask = (numBits >= 64) ? ~uintb(0) : (uintb(1) << numBits) - 1;
    entry.value = 0;
    contextNames[name] = entry;
}

void ContextDatabase::setDefault(const std::string& name, uintb value) {
    if (!hasContext(name)) {
        throw std::runtime_error("Unknown context register: " + name);
    }
    defaultValues[name] = value & contextNames[name].mask;
}

uintb ContextDatabase::getDefaultValue(const std::string& name) const {
    auto it = defaultValues.find(name);
    if (it != defaultValues.end()) {
        return it->second;
    }
    return 0;
}

void ContextDatabase::setContext(const Address& startAddr, const Address& endAddr, const std::string& name, uintb value) {
    if (!hasContext(name)) {
        throw std::runtime_error("Unknown context register: " + name);
    }

    for (auto& range : ranges) {
        if (range.startAddr == startAddr && range.endAddr == endAddr) {
            range.values[name] = value & contextNames[name].mask;
            return;
        }
    }

    ContextRange newRange;
    newRange.startAddr = startAddr;
    newRange.endAddr = endAddr;
    newRange.values[name] = value & contextNames[name].mask;
    ranges.push_back(newRange);
}

uintb ContextDatabase::getContext(const Address& addr, const std::string& name) const {
    if (!hasContext(name)) {
        return getDefaultValue(name);
    }

    for (auto it = ranges.rbegin(); it != ranges.rend(); ++it) {
        if (addr >= it->startAddr && addr <= it->endAddr) {
            auto vit = it->values.find(name);
            if (vit != it->values.end()) {
                return vit->second;
            }
        }
    }

    return getDefaultValue(name);
}

bool ContextDatabase::hasContext(const std::string& name) const {
    return contextNames.find(name) != contextNames.end();
}

int4 ContextDatabase::getContextSize(const std::string& name) const {
    auto it = contextNames.find(name);
    return (it != contextNames.end()) ? it->second.numBits : 0;
}

int4 ContextDatabase::getContextStartBit(const std::string& name) const {
    auto it = contextNames.find(name);
    return (it != contextNames.end()) ? it->second.startBit : 0;
}

void ContextDatabase::clear() {
    contextNames.clear();
    ranges.clear();
    defaultValues.clear();
}

} // namespace ghidra
