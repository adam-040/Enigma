/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file HighGlobal.h
/// \brief High-level global variable.
/// Translated from: ghidra.program.model.pcode.HighGlobal
#pragma once

#include "ghidra/pcode/HighVariable.h"
#include <vector>

namespace ghidra {
namespace pcode {

/**
 * High-level global variable.
 */
class HighGlobal : public HighVariable {
public:
    HighGlobal(HighFunction* func);

    HighGlobal(DataType* tp, Varnode* vn, const std::vector<Varnode*>& inst,
               const Address& pc, HighSymbol* sym);

    /// Convenience constructor for tests / porting.
    HighGlobal(int64_t id, const std::string& nm, Varnode* rep,
               int cat, bool readonly, int64_t addrOffset, HighFunction* func);

    bool isGlobal() const override { return true; }
    bool isParameter() const override { return false; }
    bool isConstant() const override { return false; }

    HighSymbol* getSymbol() const override { return symbol; }

    const Address& getAddr() const { return addr; }

    void decode(Decoder& decoder) override;

private:
    Address addr;
    HighSymbol* symbol;
};

}  // namespace pcode
}  // namespace ghidra
