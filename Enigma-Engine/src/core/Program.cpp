/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Program.cpp
/// \brief Main program implementation
#include <ghidra/Program.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/BookmarkManager.h>
#include <ghidra/EquateTable.h>
#include <ghidra/ExternalManager.h>
#include <ghidra/SourceFileManager.h>
#include <ghidra/RelocationTable.h>
#include <ghidra/ProgramContext.h>
#include <ghidra/PropertyMapManager.h>

namespace ghidra {

Program::Program() : name_("Untitled") {}

Program::Program(const std::string& name, Language* language, CompilerSpec* compilerSpec)
    : name_(name), language_(language), compilerSpec_(compilerSpec) {
    globalNamespace_ = std::make_unique<Namespace>("global", nullptr, Namespace::GLOBAL_NAMESPACE_ID);
    if (language_) {
        addressFactory_ = language_->getAddressFactory();
    }
}

int Program::getDefaultPointerSize() const {
    if (compilerSpec_ && compilerSpec_->getDataOrganization()) {
        return compilerSpec_->getDataOrganization()->getPointerSize();
    }
    return 4;
}

Register* Program::getRegister(const std::string& name) const {
    if (!language_) return nullptr;
    return language_->getRegister(name);
}

Register* Program::getRegister(Address addr) const {
    if (!language_) return nullptr;
    return language_->getRegister(addr.getAddressSpace(), static_cast<long>(addr.getOffset()), 4);
}

Register* Program::getRegister(Address addr, int size) const {
    if (!language_) return nullptr;
    return language_->getRegister(addr, size);
}

std::vector<Register*> Program::getRegisters(Address addr) const {
    if (!language_) return {};
    return language_->getRegisters(addr);
}

std::string Program::toString() const {
    return name_ + " (" + (language_ ? language_->toString() : "no language") + ")";
}

} // namespace ghidra
