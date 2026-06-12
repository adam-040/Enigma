/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DisassemblerContext.h
/// \brief Interface for disassembler context with future register values
/// Translated from: ghidra.program.model.lang.DisassemblerContext
#pragma once

#include <ghidra/ProcessorContext.h>
#include <ghidra/Address.h>

namespace ghidra {

class DisassemblerContext : public ProcessorContext {
public:
    virtual void setFutureRegisterValue(const Address& address, RegisterValue* value) = 0;
    virtual void setFutureRegisterValue(const Address& fromAddr, const Address& toAddr, RegisterValue* value) = 0;
};

} // namespace ghidra
