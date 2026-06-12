/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file RegisterTranslator.h
/// \brief Translates registers between language versions
/// Translated from: ghidra.program.model.lang.RegisterTranslator
#pragma once

#include <ghidra/Register.h>
#include <ghidra/Language.h>
#include <vector>
#include <unordered_map>

namespace ghidra {

class RegisterTranslator {
public:
    RegisterTranslator(Language* oldLang, Language* newLang);

    Register* getOldRegister(int offset, int size);
    Register* getNewRegister(int offset, int size);
    Register* getNewRegister(Register* oldReg);
    Register* getOldRegister(Register* newReg);

    std::vector<Register*> getNewRegisters() const { return newLang_->getRegisters(); }

private:
    struct RegisterSizeKey {
        Address address;
        int size;
        bool operator==(const RegisterSizeKey& other) const {
            return address == other.address && size == other.size;
        }
    };
    struct RegisterSizeKeyHash {
        size_t operator()(const RegisterSizeKey& k) const {
            return std::hash<uint64_t>{}(k.address.getOffset()) ^ (k.size << 8);
        }
    };

    using RegisterList = std::vector<Register*>;

    Language* oldLang_;
    Language* newLang_;
    std::unordered_map<int, RegisterList> oldRegisterMap_;
    std::unordered_map<int, RegisterList> newRegisterMap_;

    std::unordered_map<int, RegisterList> buildOffsetMap(const std::vector<Register*>& registers);
};

} // namespace ghidra
