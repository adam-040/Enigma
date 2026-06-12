/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file InstructionBlockFlow.h
/// \brief Flow entry within an InstructionBlock
/// Translated from: ghidra.program.model.lang.InstructionBlockFlow
#pragma once

#include <ghidra/Address.h>
#include <string>

namespace ghidra {

class InstructionBlockFlow {
public:
    enum class Type {
        PRIORITY,
        BRANCH,
        CALL_FALLTHROUGH,
        CALL
    };

    InstructionBlockFlow() = default;
    InstructionBlockFlow(const Address& address, const Address& flowFrom, Type type);

    Address getDestinationAddress() const { return address_; }
    Address getFlowFromAddress() const { return flowFrom_; }
    Type getType() const { return type_; }

    bool operator==(const InstructionBlockFlow& other) const;
    bool operator!=(const InstructionBlockFlow& other) const { return !(*this == other); }
    bool operator<(const InstructionBlockFlow& other) const;
    std::string toString() const;

private:
    Address address_;
    Address flowFrom_;
    Type type_ = Type::BRANCH;
};

} // namespace ghidra
