/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file RelocationHandler.h
/// \brief Extension point interface for processing relocations
/// Translated from: ghidra.program.model.reloc.RelocationHandler
#pragma once

#include <ghidra/ExtensionPoint.h>
#include <ghidra/Relocation.h>
#include <ghidra/Address.h>
#include <ghidra/MemoryAccessException.h>

namespace ghidra {

class Program;
class MemoryBlock;
class TaskMonitor;

class RelocationHandler : public ExtensionPoint {
public:
    virtual bool canRelocate(Program* program) = 0;
    virtual void relocate(Program* program, Address newImageBase, TaskMonitor* monitor) = 0;
    virtual void relocate(Program* program, MemoryBlock* block, Address newStartAddress, TaskMonitor* monitor) = 0;
    virtual void performRelocation(Program* program, const Relocation& relocation, TaskMonitor* monitor) = 0;
};

} // namespace ghidra
