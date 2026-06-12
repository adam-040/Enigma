/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Reference.h
/// \brief Interface for references between addresses and symbols
/// Translated from: ghidra.program.model.symbol.Reference
#pragma once

#include <ghidra/Address.h>
#include <ghidra/SourceType.h>
#include <cstdint>
#include <string>
#include <memory>

namespace ghidra {

class RefType;

class Reference {
public:
    static constexpr int MNEMONIC = -1;
    static constexpr int OTHER = -2;
    static constexpr int NOOperandIndex = -1;
    static constexpr int NO_MNEMONIC_INDEX = -1;
    static constexpr int FALLBACK_REF_ID = -1;

    virtual ~Reference() = default;

    virtual Address getFromAddress() const = 0;
    virtual Address getToAddress() const = 0;
    virtual bool isPrimary() const = 0;
    virtual long getSymbolID() const = 0;
    virtual const RefType* getReferenceType() const = 0;
    virtual int getOperandIndex() const = 0;
    virtual bool isMnemonicReference() const = 0;
    virtual bool isOperandReference() const = 0;
    virtual bool isStackReference() const = 0;
    virtual bool isExternalReference() const = 0;
    virtual bool isEntryPointReference() const = 0;
    virtual bool isMemoryReference() const = 0;
    virtual bool isRegisterReference() const = 0;
    virtual bool isOffsetReference() const = 0;
    virtual bool isShiftedReference() const = 0;
    virtual SourceType getSource() const = 0;

    virtual long getID() const { return FALLBACK_REF_ID; }
    virtual std::string toString() const = 0;

    virtual bool operator==(const Reference& other) const;
    virtual bool operator!=(const Reference& other) const;
};

} // namespace ghidra
