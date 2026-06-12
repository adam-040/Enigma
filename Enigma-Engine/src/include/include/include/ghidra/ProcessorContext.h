/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ProcessorContext.h
/// \brief Interface for processor register state with write support
/// Translated from: ghidra.program.model.lang.ProcessorContext
#pragma once

#include <ghidra/ProcessorContextView.h>
#include <ghidra/ContextChangeException.h>
#include <cstdint>

namespace ghidra {

class ProcessorContext : public ProcessorContextView {
public:
    virtual void setValue(Register* reg, uint64_t value) = 0;
    virtual void setRegisterValue(RegisterValue* value) = 0;
    virtual void clearRegister(Register* reg) = 0;
};

} // namespace ghidra
