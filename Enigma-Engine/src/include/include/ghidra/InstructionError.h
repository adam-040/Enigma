/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file InstructionError.h
/// \brief Describes an error encountered when adding a disassembly block to a program.
/// Translated from: ghidra.program.model.lang.InstructionError
#pragma once

#include "ghidra/Address.h"
#include "ghidra/InstructionBlock.h"
#include "ghidra/RegisterValue.h"
#include <string>

namespace ghidra {

class InstructionError {
public:
    enum class InstructionErrorType {
        DUPLICATE,
        INSTRUCTION_CONFLICT,
        DATA_CONFLICT,
        OFFCUT_INSTRUCTION,
        PARSE,
        MEMORY,
        FLOW_ALIGNMENT
    };

    InstructionError(InstructionBlock* block, InstructionErrorType type,
                     const Address& instructionAddress, const Address& conflictAddress,
                     const Address& flowFromAddress, const std::string& message);

    InstructionError(InstructionBlock* block, const RegisterValue& contextValue,
                     const Address& instructionAddress, const Address& flowFromAddress,
                     const std::string& message);

    InstructionBlock* getInstructionBlock() const { return block; }
    InstructionErrorType getInstructionErrorType() const { return type; }
    bool isInstructionConflict() const;
    bool isOffcutError() const;
    const Address& getInstructionAddress() const { return instructionAddress; }
    const Address& getConflictAddress() const { return conflictAddress; }
    const RegisterValue& getParseContextValue() const { return parseContext; }
    const Address& getFlowFromAddress() const { return flowFromAddress; }
    const std::string& getConflictMessage() const { return message; }

    static bool isConflictType(InstructionErrorType t);

private:
    InstructionBlock* block;
    InstructionErrorType type;
    Address conflictAddress;
    Address instructionAddress;
    RegisterValue parseContext;
    Address flowFromAddress;
    std::string message;
};

} // namespace ghidra
