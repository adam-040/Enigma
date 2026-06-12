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
#include <vector>

namespace ghidra {

class CodeBlock;

/**
 * MultEntSubIterator iterates over multi-entry subroutines.
 * Translated from: ghidra.program.model.block.MultEntSubIterator
 */
class MultEntSubIterator : public CodeBlockIterator {
public:
    MultEntSubIterator() = default;
    explicit MultEntSubIterator(const std::vector<CodeBlock*>& blocks);
    ~MultEntSubIterator() override = default;
};

} // namespace ghidra
