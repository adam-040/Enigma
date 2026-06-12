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

#include <list>
#include "ghidra/correlate/Hash.h"

namespace ghidra {

class InstructHash;

class HashEntry {
public:
    Hash hash;
    std::list<InstructHash*> instList;

    HashEntry() = default;
    explicit HashEntry(const Hash& h) : hash(h) {}

    bool hasDuplicateBlocks();
};

} // namespace ghidra
