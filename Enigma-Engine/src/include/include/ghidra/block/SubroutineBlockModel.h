/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once

#include <ghidra/block/CodeBlockModel.h>

namespace ghidra {

class AddressSetView;
class CodeBlock;
class CodeBlockIterator;
class TaskMonitor;
class CancelledException;

/**
 * SubroutineBlockModel defines the interface for subroutine block models.
 * Translated from: ghidra.program.model.block.SubroutineBlockModel
 */
class SubroutineBlockModel : public CodeBlockModel {
public:
    ~SubroutineBlockModel() override = default;

    virtual CodeBlock* getSubroutine(Address addr, TaskMonitor& monitor) = 0;

    virtual CodeBlockIterator getSubroutines(TaskMonitor& monitor) = 0;

    virtual CodeBlockIterator getSubroutines(const AddressSetView& addrSet, TaskMonitor& monitor) = 0;

    bool isSubroutineModel() const override { return true; }
};

} // namespace ghidra
