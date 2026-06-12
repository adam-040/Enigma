/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file HighConstant.h
/// \brief A constant that has been given a datatype (like a constant that is really a pointer).
/// Translated from: ghidra.program.model.pcode.HighConstant
#pragma once

#include "ghidra/pcode/HighVariable.h"
#include "ghidra/Address.h"
#include <cstdint>

namespace ghidra {
namespace pcode {

class HighConstant : public HighVariable {
public:
    HighConstant(HighFunction* func);
    HighConstant(const std::string& name, DataType* type, Varnode* vn,
                 const Address& pc, HighFunction* func);

    /// Convenience constructor for tests / porting.
    HighConstant(int64_t id, const std::string& nm, Varnode* rep,
                 int cat, int64_t value, HighFunction* func);

    HighSymbol* getSymbol() const override { return symbol; }
    const Address& getPCAddress() const { return pcaddr; }

    bool isConstant() const override { return true; }
    bool isParameter() const override { return false; }
    bool isGlobal() const override { return false; }

    int64_t getScalarValue() const;
    int getScalarBitLength() const { return getSize() * 8; }

    void decode(Decoder& decoder) override;

private:
    Address pcaddr;
    HighSymbol* symbol;
    int64_t value;
};

}  // namespace pcode
}  // namespace ghidra
