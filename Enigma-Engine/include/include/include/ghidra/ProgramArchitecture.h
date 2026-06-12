/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ProgramArchitecture.h
/// \brief Identifies program architecture details for language/compiler-specific storage
/// Translated from: ghidra.program.model.lang.ProgramArchitecture
#pragma once

#include "ghidra/CompilerSpec.h"
#include "ghidra/Language.h"
#include "ghidra/AddressFactory.h"

namespace ghidra {

class LanguageCompilerSpecPair;

class ProgramArchitecture {
public:
    virtual ~ProgramArchitecture() = default;
    virtual Language* getLanguage() = 0;
    virtual AddressFactory* getAddressFactory() = 0;
    virtual CompilerSpec* getCompilerSpec() = 0;
};

} // namespace ghidra
