/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file UnknownRegister.h
/// \brief Used when a register is requested for an undefined location
/// Translated from: ghidra.program.model.lang.UnknownRegister
#pragma once

#include "ghidra/Register.h"

namespace ghidra {

class UnknownRegister : public Register {
public:
    UnknownRegister(const std::string& name, const std::string& description,
                    const Address& address, int numBytes, bool bigEndian, int typeFlags)
        : Register(name, description, address, numBytes, bigEndian, typeFlags) {}
};

} // namespace ghidra
