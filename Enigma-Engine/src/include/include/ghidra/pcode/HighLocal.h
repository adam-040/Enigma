/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file HighLocal.h
/// \brief High-level local variable.
/// Translated from: ghidra.program.model.pcode.HighLocal
#pragma once

#include "ghidra/pcode/HighVariable.h"
#include <vector>

namespace ghidra {
namespace pcode {

/**
 * High-level local variable within a function.
 */
class HighLocal : public HighVariable {
public:
    HighLocal(HighFunction* func);

    HighLocal(DataType* type, Varnode* vn, const std::vector<Varnode*>& inst,
              const Address& pc, HighSymbol* sym);

    /// Convenience constructor for tests / porting.
    HighLocal(int64_t id, const std::string& nm, Varnode* rep,
              int cat, bool readonly, int slot, int catIndex, HighFunction* func);

    HighSymbol* getSymbol() const override { return symbol; }
    const Address& getPCAddress() const { return pcaddr; }

    int getSlot() const { return slot; }
    void setSlot(int s) { slot = s; }
    int64_t getFirstUseOffset() const { return firstUseOffset; }
    void setFirstUseOffset(int64_t o) { firstUseOffset = o; }

    void decode(Decoder& decoder) override;

protected:
    Address pcaddr;
    HighSymbol* symbol;
    int slot;
    int64_t firstUseOffset;
};

}  // namespace pcode
}  // namespace ghidra
