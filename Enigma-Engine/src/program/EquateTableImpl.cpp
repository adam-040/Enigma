/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file EquateTableImpl.cpp
/// \brief Implementation of equate table
/// Translated from: ghidra.program.database.symbol.EquateTableDB

#include <ghidra/EquateTableImpl.h>
#include <ghidra/Address.h>
#include <ghidra/Encoder.h>
#include <ghidra/Decoder.h>

namespace ghidra {

Equate* EquateTableImpl::createEquate(const std::string& name, int64_t value) {
    auto eq = std::make_unique<Equate>(name, value);
    Equate* raw = eq.get();
    equates_.push_back(std::move(eq));
    equatesByName_[name] = raw;
    equatesByValue_[value] = raw;
    return raw;
}

Equate* EquateTableImpl::getEquate(const std::string& name) {
    auto it = equatesByName_.find(name);
    return (it != equatesByName_.end()) ? it->second : nullptr;
}

Equate* EquateTableImpl::getEquate(int64_t value) {
    auto it = equatesByValue_.find(value);
    return (it != equatesByValue_.end()) ? it->second : nullptr;
}

std::vector<Equate*> EquateTableImpl::getEquates() {
    std::vector<Equate*> result;
    for (const auto& eq : equates_) {
        result.push_back(eq.get());
    }
    return result;
}

Equate* EquateTableImpl::getEquate(const Address& addr, int opndPosition, int64_t value) {
    auto it = opndRefs_.find(makeKey(addr, opndPosition));
    if (it == opndRefs_.end()) return nullptr;
    for (Equate* e : it->second) {
        if (e->getValue() == value) return e;
    }
    return nullptr;
}

std::vector<Equate*> EquateTableImpl::getEquates(const Address& addr, int opndPosition) {
    auto it = opndRefs_.find(makeKey(addr, opndPosition));
    if (it == opndRefs_.end()) return {};
    return it->second;
}

std::vector<Equate*> EquateTableImpl::getEquates(const Address& addr) {
    std::vector<Equate*> out;
    int64_t base = static_cast<int64_t>(addr.getOffset()) << 8;
    for (int opnd = 0; opnd < 16; ++opnd) {
        auto it = opndRefs_.find(static_cast<uint64_t>(base | opnd));
        if (it != opndRefs_.end()) {
            for (Equate* e : it->second) {
                out.push_back(e);
            }
        }
    }
    return out;
}

void EquateTableImpl::removeEquate(const Address& addr, int opndPosition, int64_t value) {
    auto key = makeKey(addr, opndPosition);
    auto it = opndRefs_.find(key);
    if (it == opndRefs_.end()) return;
    auto& vec = it->second;
    for (auto vit = vec.begin(); vit != vec.end(); ++vit) {
        if ((*vit)->getValue() == value) {
            vec.erase(vit);
            if (vec.empty()) opndRefs_.erase(key);
            return;
        }
    }
}

void EquateTableImpl::removeEquate(Equate* equate) {
    if (equate == nullptr) return;
    int64_t value = equate->getValue();
    const std::string& name = equate->getName();
    equatesByValue_.erase(value);
    equatesByName_.erase(name);
    for (auto& kv : opndRefs_) {
        auto& vec = kv.second;
        for (auto vit = vec.begin(); vit != vec.end(); ) {
            if (*vit == equate) vit = vec.erase(vit);
            else ++vit;
        }
    }
    for (auto it = equates_.begin(); it != equates_.end(); ++it) {
        if (it->get() == equate) {
            equates_.erase(it);
            break;
        }
    }
}

Equate* EquateTableImpl::createEquate(const std::string& name, int64_t value,
                                      const Address& addr, int opndPosition) {
    Equate* e = createEquate(name, value);
    opndRefs_[makeKey(addr, opndPosition)].push_back(e);
    return e;
}

bool EquateTableImpl::addReference(Equate* equate, const Address& addr, int opndPosition) {
    if (equate == nullptr) return false;
    auto& refs = opndRefs_[makeKey(addr, opndPosition)];
    for (Equate* e : refs) {
        if (e == equate) return true;
    }
    refs.push_back(equate);
    return true;
}

std::vector<EquateTable::Binding> EquateTableImpl::getAllBindings() {
    std::vector<Binding> out;
    for (const auto& kv : opndRefs_) {
        const uint64_t off = kv.first >> 8;
        const int16_t opnd = static_cast<int16_t>(kv.first & 0xff);
        for (Equate* e : kv.second) {
            out.push_back(Binding{e, off, opnd});
        }
    }
    return out;
}

EquateTableImpl::OpndKey EquateTableImpl::makeKey(const Address& addr, int opnd) {
    uint64_t off = static_cast<uint64_t>(addr.getOffset());
    return (off << 8) | (static_cast<uint64_t>(opnd) & 0xff);
}

void EquateTableImpl::saveXml(Encoder& /*encoder*/, int /*sourceType*/) const {}

void EquateTableImpl::decode(Decoder& /*decoder*/, HighFunction* /*func*/) {}

} // namespace ghidra
