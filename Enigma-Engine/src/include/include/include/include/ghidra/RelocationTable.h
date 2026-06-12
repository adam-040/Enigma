/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file RelocationTable.h
/// \brief Relocation table interface
/// Translated from: ghidra.program.model.reloc.RelocationTable
#pragma once

#include <ghidra/Address.h>
#include <ghidra/Relocation.h>
#include <vector>

namespace ghidra {

class RelocationTable {
public:
    virtual ~RelocationTable() = default;

    virtual std::vector<Relocation> getRelocations() = 0;
    virtual std::vector<Relocation> getRelocations(Address addr) = 0;
    virtual int getRelocationCount() = 0;
};

} // namespace ghidra
