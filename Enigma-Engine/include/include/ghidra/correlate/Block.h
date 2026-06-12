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

#include <vector>
#include "ghidra/correlate/Hash.h"

namespace ghidra {

class CodeBlock;
class InstructHash;
class HashCalculator;
class MemoryAccessException;

class Block {
public:
    bool isMatched;
    bool isVisited;
    CodeBlock* origBlock;
    std::vector<InstructHash*> instList;

    explicit Block(CodeBlock* codeBlock);

    int getMatchHash() const { return matchHash_; }

    void clearSort();
    void setMatched(int index);
    bool allUnknown(int startindex, int length);
    int hashGram(int gramSize, InstructHash* instHash, HashCalculator* hashCalc);
    void calcHashes(int minLength, int maxLength, bool wholeBlock, bool matchOnly, HashCalculator* hashCalc);

private:
    int matchHash_ = 0;
};

} // namespace ghidra
