/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/correlate/Block.h"
#include "ghidra/correlate/InstructHash.h"
#include "ghidra/correlate/HashCalculator.h"
#include "ghidra/block/CodeBlock.h"
#include "ghidra/MemoryAccessException.h"

namespace ghidra {

Block::Block(CodeBlock* codeBlock)
    : isMatched(false), isVisited(false), origBlock(codeBlock) {
}

void Block::clearSort() {
    for (InstructHash* element : instList) {
        element->clearSort();
    }
}

void Block::setMatched(int index) {
    isMatched = true;
    matchHash_ = index * 7919;
    matchHash_ += 511;
    matchHash_ *= 4691;
}

bool Block::allUnknown(int startindex, int length) {
    for (int i = 0; i < length; ++i) {
        if (instList[startindex + i]->isMatched)
            return false;
    }
    return true;
}

int Block::hashGram(int gramSize, InstructHash* instHash, HashCalculator* hashCalc) {
    int hashVal = Hash::SEED;
    for (int i = 0; i < gramSize; ++i) {
        InstructHash* curHash = instList[instHash->index + i];
        hashVal = hashCalc->calcHash(hashVal, curHash->instruction);
    }
    return hashVal;
}

void Block::calcHashes(int minLength, int maxLength, bool wholeBlock, bool matchOnly, HashCalculator* hashCalc) {
    if (wholeBlock && static_cast<int>(instList.size()) < minLength) {
        minLength = static_cast<int>(instList.size());
        maxLength = static_cast<int>(instList.size());
    }
    else if (matchOnly && matchHash_ == 0 && instList.size() > 8) {
        for (size_t i = 0; i < instList.size(); ++i) {
            if (!instList[i]->isMatched)
                instList[i]->clearNGrams(0);
        }
        return;
    }
    for (size_t i = 0; i < instList.size(); ++i) {
        if (instList[i]->isMatched) continue;
        int maxind;
        if (static_cast<int>(i) + minLength > static_cast<int>(instList.size())) {
            instList[i]->clearNGrams(0);
            continue;
        }
        maxind = static_cast<int>(i) + maxLength;
        if (maxind > static_cast<int>(instList.size())) {
            maxind = static_cast<int>(instList.size());
        }
        int num = maxind - static_cast<int>(i) - minLength + 1;
        instList[i]->clearNGrams(num);
        int accum = (i == 0 && instList.size() > 8) ? Hash::SEED : Hash::ALTERNATE_SEED;

        for (int j = 0; j < minLength - 1; ++j) {
            if (accum != 0) {
                if (instList[i + j]->isMatched) {
                    accum = 0;
                    break;
                }
                accum = hashCalc->calcHash(accum, instList[i + j]->instruction);
            }
        }

        for (int j = 0; j < num; ++j) {
            if (accum != 0) {
                if (instList[i + j + minLength - 1]->isMatched)
                    accum = 0;
                else
                    accum = hashCalc->calcHash(accum, instList[i + j + minLength - 1]->instruction);
            }
            if (accum != 0) {
                instList[i]->nGrams[j] = Hash(accum ^ matchHash_, minLength + j);
            }
            else {
                instList[i]->nGrams[j] = Hash();
            }
        }
    }
}

} // namespace ghidra
