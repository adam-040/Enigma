/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file InstructionContext.h
/// \brief Provides access to instruction data and context-register storage during parse
/// Translated from: ghidra.program.model.lang.InstructionContext
#pragma once

#include "ghidra/Address.h"
#include "ghidra/MemBuffer.h"
#include "ghidra/MemoryAccessException.h"
#include "ghidra/ProcessorContextView.h"
#include "ghidra/ParserContext.h"
#include "ghidra/UnknownContextException.h"

namespace ghidra {

class InstructionContext {
public:
    virtual ~InstructionContext() = default;
    virtual Address getAddress() const = 0;
    virtual ProcessorContextView* getProcessorContext() = 0;
    virtual MemBuffer* getMemBuffer() = 0;
    virtual ParserContext* getParserContext() = 0;
    virtual ParserContext* getParserContext(const Address& instructionAddress) = 0;
};

} // namespace ghidra
