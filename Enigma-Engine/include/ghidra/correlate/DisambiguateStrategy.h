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

class InstructHash;
class HashStore;
class CancelledException;
class MemoryAccessException;

class DisambiguateStrategy {
public:
    virtual ~DisambiguateStrategy() = default;
    virtual std::vector<Hash> calcHashes(InstructHash* instHash, int matchSize, HashStore* store) = 0;
};

} // namespace ghidra
