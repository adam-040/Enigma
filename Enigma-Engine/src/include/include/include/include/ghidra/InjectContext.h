/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file InjectContext.h
/// \brief Context for p-code injection.
/// Translated from: ghidra.program.model.lang.InjectContext
#pragma once

#include <ghidra/Address.h>
#include <ghidra/Decoder.h>
#include <vector>

namespace ghidra {

class Language;
class Varnode;

class InjectContext {
public:
    Language* language = nullptr;
    Address baseAddr;
    Address nextAddr;
    Address callAddr;
    Address refAddr;
    std::vector<Varnode*> inputlist;
    std::vector<Varnode*> output;

    InjectContext() = default;

    void decode(Decoder& decoder);
};

} // namespace ghidra
