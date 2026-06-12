/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file EquateSymbol.h
/// \brief High-level equate symbol.
/// Translated from: ghidra.program.model.pcode.EquateSymbol
#pragma once

#include "ghidra/HighSymbol.h"
#include "ghidra/Address.h"
#include <cstdint>
#include <string>

namespace ghidra {
namespace pcode {

class HighFunction;

class EquateSymbol : public HighSymbol {
public:
    static constexpr int FORMAT_DEFAULT = 0;
    static constexpr int FORMAT_HEX = 1;
    static constexpr int FORMAT_DEC = 2;
    static constexpr int FORMAT_OCT = 3;
    static constexpr int FORMAT_BIN = 4;
    static constexpr int FORMAT_CHAR = 5;
    static constexpr int FORMAT_FLOAT = 6;
    static constexpr int FORMAT_DOUBLE = 7;

    EquateSymbol(HighFunction* func);
    EquateSymbol(int64_t uniqueId, const std::string& nm, int64_t val,
                 HighFunction* func, const Address& addr, int64_t hash);
    EquateSymbol(int64_t uniqueId, int conv, int64_t val,
                 HighFunction* func, const Address& addr, int64_t hash);

    int64_t getValue() const { return value; }
    int getConvert() const { return convert; }

    void decode(Decoder& decoder) override;
    void encode(Encoder& encoder) const override;

    static std::string getIntegerFormatString(int convert);
    static int getFormatStringValue(const std::string& format);

    /// Inspect a name to detect what numeric format it is in.
    static int convertName(const std::string& nm, int64_t val);

private:
    int64_t value;
    int convert;
};

}  // namespace pcode
}  // namespace ghidra
