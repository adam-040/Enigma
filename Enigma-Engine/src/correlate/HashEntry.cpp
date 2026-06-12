/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/correlate/HashEntry.h"
#include "ghidra/correlate/Block.h"
#include "ghidra/correlate/InstructHash.h"

namespace ghidra {

bool HashEntry::hasDuplicateBlocks() {
    bool res = false;
    for (InstructHash* curInstruct : instList) {
        if (curInstruct->block->isVisited) {
            res = true;
            break;
        }
        curInstruct->block->isVisited = true;
    }
    for (InstructHash* curInstruct : instList) {
        curInstruct->block->isVisited = false;
    }
    return res;
}

} // namespace ghidra
