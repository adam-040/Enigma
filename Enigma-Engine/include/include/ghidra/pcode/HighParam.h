/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file HighParam.h
/// \brief High-level function parameter.
/// Translated from: ghidra.program.model.pcode.HighParam
#pragma once

#include "ghidra/pcode/HighLocal.h"
#include <vector>

namespace ghidra {
namespace pcode {

class HighParam : public HighLocal {
public:
    HighParam(HighFunction* func);

    HighParam(DataType* tp, Varnode* rep, const Address& pc, int slot, HighSymbol* sym);

    /// Convenience constructor for tests / porting.
    HighParam(int64_t id, const std::string& nm, Varnode* rep,
              int cat, bool readonly, int slot, int catIndex, HighFunction* func);

    bool isParameter() const override { return true; }
    bool isConstant() const override { return false; }

    void decode(Decoder& decoder) override;
};

}  // namespace pcode
}  // namespace ghidra
