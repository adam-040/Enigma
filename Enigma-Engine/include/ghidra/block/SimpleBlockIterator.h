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

#include <ghidra/block/CodeBlockIterator.h>
#include <ghidra/block/CodeBlock.h>
#include <vector>

namespace ghidra {

class SimpleBlockModel;

/**
 * SimpleBlockIterator iterates over basic blocks within a model.
 * Translated from: ghidra.program.model.block.SimpleBlockIterator
 */
class SimpleBlockIterator : public CodeBlockIterator {
public:
    SimpleBlockIterator() = default;
    SimpleBlockIterator(SimpleBlockModel* model, const std::vector<CodeBlock*>& blocks);
    ~SimpleBlockIterator() override = default;
};

} // namespace ghidra
