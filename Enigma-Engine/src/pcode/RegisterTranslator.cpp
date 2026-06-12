#include <ghidra/RegisterTranslator.h>
#include <algorithm>

namespace ghidra {

RegisterTranslator::RegisterTranslator(Language* oldLang, Language* newLang)
    : oldLang_(oldLang), newLang_(newLang) {
    oldRegisterMap_ = buildOffsetMap(oldLang_->getRegisters());
    newRegisterMap_ = buildOffsetMap(newLang_->getRegisters());
}

std::unordered_map<int, RegisterTranslator::RegisterList>
RegisterTranslator::buildOffsetMap(const std::vector<Register*>& registers) {
    std::unordered_map<int, RegisterList> offsetMap;
    for (auto* reg : registers) {
        auto addr = reg->getAddress();
        if (!addr.isRegisterAddress()) continue;
        auto space = reg->getAddressSpace();
        if (space && space->getName() != "register") continue;
        int offset = static_cast<int>(addr.getOffset());
        auto& list = offsetMap[offset];
        list.push_back(reg);
    }
    for (auto& kv : offsetMap) {
        auto& list = kv.second;
        std::sort(list.begin(), list.end(), [](Register* a, Register* b) {
            return a->getBitLength() > b->getBitLength();
        });
    }
    return offsetMap;
}

Register* RegisterTranslator::getOldRegister(int offset, int size) {
    auto it = oldRegisterMap_.find(offset);
    if (it == oldRegisterMap_.end()) return nullptr;
    auto& list = it->second;
    if (size == 0) return list[0];
    for (int i = static_cast<int>(list.size()) - 1; i >= 0; --i) {
        if (list[i]->getMinimumByteSize() >= size) return list[i];
    }
    return nullptr;
}

Register* RegisterTranslator::getNewRegister(int offset, int size) {
    auto it = newRegisterMap_.find(offset);
    if (it == newRegisterMap_.end()) return nullptr;
    auto& list = it->second;
    if (size == 0) return list[0];
    for (int i = static_cast<int>(list.size()) - 1; i >= 0; --i) {
        if (list[i]->getMinimumByteSize() >= size) return list[i];
    }
    return nullptr;
}

Register* RegisterTranslator::getNewRegister(Register* oldReg) {
    return newLang_->getRegister(oldReg->getName());
}

Register* RegisterTranslator::getOldRegister(Register* newReg) {
    return oldLang_->getRegister(newReg->getName());
}

} // namespace ghidra
