/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ThunkReference.h
/// \brief Concrete thunk function reference
/// Translated from: ghidra.program.model.symbol.ThunkReference
#pragma once

#include <ghidra/DynamicReference.h>
#include <ghidra/Address.h>
#include <ghidra/SourceType.h>

namespace ghidra {

class RefType;

class ThunkReference : public DynamicReference {
public:
    ThunkReference(Address thunkAddr, Address thunkedAddr);

    Address getFromAddress() const override { return fromAddr_; }
    Address getToAddress() const override { return toAddr_; }
    bool isPrimary() const override { return false; }
    long getSymbolID() const override { return -1; }
    const RefType* getReferenceType() const override;
    int getOperandIndex() const override { return OTHER; }
    bool isMnemonicReference() const override { return true; }
    bool isOperandReference() const override { return false; }
    bool isStackReference() const override { return false; }
    bool isExternalReference() const override { return false; }
    bool isEntryPointReference() const override { return false; }
    bool isMemoryReference() const override { return false; }
    bool isRegisterReference() const override { return false; }
    bool isOffsetReference() const override { return false; }
    bool isShiftedReference() const override { return false; }
    SourceType getSource() const override { return SourceType::DEFAULT; }

    std::string toString() const override;

    bool operator==(const Reference& other) const override;
    bool operator!=(const Reference& other) const override;

private:
    Address fromAddr_;
    Address toAddr_;
};

} // namespace ghidra
