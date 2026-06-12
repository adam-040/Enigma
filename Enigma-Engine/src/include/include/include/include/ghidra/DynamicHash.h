/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DynamicHash.h
/// \brief Hashes Varnode identity within a function's syntax tree.
/// Translated from: ghidra.program.model.pcode.DynamicHash
#pragma once

#include <ghidra/Address.h>
#include <cstdint>

namespace ghidra {

class Varnode;
class HighFunction;

/**
 * Hashes a Varnode's identity based on local information in the syntax tree near
 * the Varnode. The hash provides a stable identifier for a Varnode whose storage
 * address is too ephemeral (e.g. temporary "unique" address space).
 *
 * Currently a stub. The full Java implementation walks the syntax tree to
 * compute the hash; this port provides the storage layout and accessors only.
 */
class DynamicHash {
public:
    DynamicHash();
    DynamicHash(Varnode* vn, HighFunction* hf);

    int64_t getHash() const { return hash; }
    const Address& getAddress() const { return address; }

    static int64_t hashVarnode(Varnode* vn, HighFunction* hf);
    static int64_t hashPcodeOp(void* op, HighFunction* hf);

private:
    Address address;
    int64_t hash;
};

} // namespace ghidra
