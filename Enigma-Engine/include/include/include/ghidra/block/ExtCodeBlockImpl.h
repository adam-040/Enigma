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

#include <ghidra/block/CodeBlockImpl.h>

namespace ghidra {

class CodeBlockModel;
class Program;

/**
 * ExtCodeBlockImpl represents an external code block (outside the program's memory).
 * Translated from: ghidra.program.model.block.ExtCodeBlockImpl
 */
class ExtCodeBlockImpl : public CodeBlockImpl {
public:
    ExtCodeBlockImpl(CodeBlockModel* model, Program* program, const std::string& name);

    ~ExtCodeBlockImpl() override = default;

    bool hasValidSymbol() const override;

    CodeBlockReferenceIterator* getSources(TaskMonitor& monitor) override;
    CodeBlockReferenceIterator* getDestinations(TaskMonitor& monitor) override;

    int getNumSources(TaskMonitor& monitor) override;
    int getNumDestinations(TaskMonitor& monitor) override;
};

} // namespace ghidra
