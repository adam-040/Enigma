/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file VarnodeTranslator.h
/// \brief Helper to translate between Pcode Varnodes and Registers.
/// Translated from: ghidra.program.model.pcode.VarnodeTranslator
#pragma once

#include <vector>
#include <string>

namespace ghidra {

class Language;
class Varnode;
class Register;
class Program;

/**
 * Helper to translate from Pcode Varnodes to Registers (and vice versa).
 * The backing Language is supplied either directly or via a Program.
 */
class VarnodeTranslator {
public:
    explicit VarnodeTranslator(Language* lang);
    explicit VarnodeTranslator(Program* program);

    bool supportsPcode() const;

    /// Translate a Varnode into its underlying Register (or nullptr).
    Register* getRegister(Varnode* node) const;

    /// Build a Varnode that represents the given register.
    Varnode* getVarnode(Register* reg) const;

    /// Look up a Register by name.
    Register* getRegister(const std::string& name) const;

    /// All defined registers of the backing language.
    std::vector<Register*> getRegisters() const;

private:
    Language* language;
};

}  // namespace ghidra
