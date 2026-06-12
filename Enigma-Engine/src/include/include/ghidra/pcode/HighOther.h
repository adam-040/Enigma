/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file HighOther.h
/// \brief Catch-all for compiler infrastructure variables (stackpointer, saved regs, etc.).
/// Translated from: ghidra.program.model.pcode.HighOther
#pragma once

#include "ghidra/pcode/HighVariable.h"
#include <vector>

namespace ghidra {
namespace pcode {

/**
 * Catch-all for compiler-infrastructure variables that are not parameters,
 * locals, globals, or constants (e.g. stackpointer, saved registers).
 */
class HighOther : public HighVariable {
public:
    HighOther(HighFunction* func);

    HighOther(DataType* type, Varnode* vn, const std::vector<Varnode*>& inst,
              const Address& pc, HighSymbol* sym);

    /// Convenience constructor for tests / porting.
    HighOther(int64_t id, const std::string& nm, Varnode* rep,
              int cat, int slot, HighFunction* func);

    HighSymbol* getSymbol() const override { return symbol; }
    const Address& getPCAddress() const { return pcaddr; }

    int getSlot() const { return slot; }
    void setSlot(int s) { slot = s; }

    bool isParameter() const override { return false; }
    bool isConstant() const override { return false; }
    bool isGlobal() const override { return false; }

    void decode(Decoder& decoder) override;

private:
    Address pcaddr;
    HighSymbol* symbol;
    int slot;
};

}  // namespace pcode
}  // namespace ghidra
