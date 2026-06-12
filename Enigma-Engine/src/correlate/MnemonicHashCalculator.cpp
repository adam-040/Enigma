/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/correlate/MnemonicHashCalculator.h"
#include "ghidra/Instruction.h"
#include "ghidra/SimpleCRC32.h"
#include <string>

namespace ghidra {

int MnemonicHashCalculator::calcHash(int startHash, Instruction* inst) {
    std::string mnemonic = inst->getMnemonicString();
    for (size_t i = 0; i < mnemonic.size(); ++i) {
        startHash = SimpleCRC32::hashOneByte(startHash, static_cast<int>(mnemonic[i]));
    }
    return startHash;
}

} // namespace ghidra
