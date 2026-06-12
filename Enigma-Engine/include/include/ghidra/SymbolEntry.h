/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SymbolEntry.h
/// \brief Mapping from a HighSymbol to the storage that holds the symbol's value.
/// Translated from: ghidra.program.model.pcode.SymbolEntry
#pragma once

#include <ghidra/Address.h>
#include <ghidra/ElementId.h>
#include <ghidra/AttributeId.h>
#include <ghidra/Encoder.h>
#include <ghidra/Decoder.h>
#include <cstdint>
#include <stdexcept>

namespace ghidra {

class HighSymbol;
class VariableStorage;

class DecoderException : public std::runtime_error {
public:
    explicit DecoderException(const std::string& msg) : std::runtime_error(msg) {}
};

/**
 * A mapping from a HighSymbol object to the storage that holds the symbol's value.
 */
class SymbolEntry {
public:
    virtual ~SymbolEntry() = default;

    /// @return the HighSymbol owning this entry
    HighSymbol* getSymbol() const { return symbol; }

    /// @return the start of the code range where this entry applies (or empty Address)
    const Address& getPCAdress() const { return pcaddr; }

    /// Decode this entry from the stream. Typically more than one element is consumed.
    virtual void decode(Decoder& decoder) = 0;

    /// Encode this entry as (a set of) elements to the given stream
    virtual void encode(Encoder& encoder) const = 0;

    /// @return the storage associated with this particular mapping of the Symbol
    virtual VariableStorage getStorage() const = 0;

    /// @return the number of bytes consumed by the symbol when using this storage
    virtual int getSize() const = 0;

    /// @return one of MutabilitySettingsDefinition::NORMAL / VOLATILE / CONSTANT
    virtual int getMutability() const = 0;

protected:
    HighSymbol* symbol;
    Address pcaddr;

    SymbolEntry(HighSymbol* sym) : symbol(sym), pcaddr() {}

    void decodeRangeList(Decoder& decoder);

    void encodeRangelist(Encoder& encoder) const;
};

} // namespace ghidra
