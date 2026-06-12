/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file InstructionError.cpp
#include "ghidra/InstructionError.h"

namespace ghidra {

InstructionError::InstructionError(InstructionBlock* block, InstructionErrorType type,
                                   const Address& instructionAddress, const Address& conflictAddress,
                                   const Address& flowFromAddress, const std::string& message)
    : block(block), type(type), conflictAddress(conflictAddress),
      instructionAddress(instructionAddress), flowFromAddress(flowFromAddress), message(message) {}

InstructionError::InstructionError(InstructionBlock* block, const RegisterValue& contextValue,
                                   const Address& instructionAddress, const Address& flowFromAddress,
                                   const std::string& message)
    : block(block), type(InstructionErrorType::PARSE), parseContext(contextValue),
      instructionAddress(instructionAddress), flowFromAddress(flowFromAddress), message(message) {}

bool InstructionError::isInstructionConflict() const {
    return type == InstructionErrorType::OFFCUT_INSTRUCTION ||
           type == InstructionErrorType::INSTRUCTION_CONFLICT;
}

bool InstructionError::isOffcutError() const {
    return type == InstructionErrorType::OFFCUT_INSTRUCTION;
}

bool InstructionError::isConflictType(InstructionErrorType t) {
    return t == InstructionErrorType::DUPLICATE ||
           t == InstructionErrorType::INSTRUCTION_CONFLICT ||
           t == InstructionErrorType::DATA_CONFLICT ||
           t == InstructionErrorType::OFFCUT_INSTRUCTION;
}

} // namespace ghidra
