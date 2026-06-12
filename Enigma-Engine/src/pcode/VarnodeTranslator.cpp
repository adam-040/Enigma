/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file VarnodeTranslator.cpp
/// \brief VarnodeTranslator implementation.
#include "ghidra/VarnodeTranslator.h"
#include "ghidra/Language.h"
#include "ghidra/Register.h"
#include "ghidra/Varnode.h"
#include "ghidra/Program.h"

namespace ghidra {

VarnodeTranslator::VarnodeTranslator(Language* lang) : language(lang) {}

VarnodeTranslator::VarnodeTranslator(Program* program)
    : language(program ? program->getLanguage() : nullptr) {}

bool VarnodeTranslator::supportsPcode() const {
    return language != nullptr && language->supportsPcode();
}

Register* VarnodeTranslator::getRegister(Varnode* node) const {
    if (node == nullptr || language == nullptr) return nullptr;
    return language->getRegister(node->getAddress(), node->getSize());
}

Varnode* VarnodeTranslator::getVarnode(Register* reg) const {
    if (reg == nullptr) return nullptr;
    return new Varnode(reg->getAddress(), reg->getMinimumByteSize());
}

Register* VarnodeTranslator::getRegister(const std::string& name) const {
    if (language == nullptr) return nullptr;
    return language->getRegister(name);
}

std::vector<Register*> VarnodeTranslator::getRegisters() const {
    if (language == nullptr) return {};
    return language->getRegisters();
}

}  // namespace ghidra
