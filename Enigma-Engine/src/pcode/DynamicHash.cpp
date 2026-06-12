/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DynamicHash.cpp
/// \brief Hashes Varnode identity within a function's syntax tree.
#include "ghidra/DynamicHash.h"

namespace ghidra {

DynamicHash::DynamicHash() : hash(0) {}

DynamicHash::DynamicHash(Varnode* /*vn*/, HighFunction* /*hf*/) : hash(0) {}

int64_t DynamicHash::hashVarnode(Varnode* /*vn*/, HighFunction* /*hf*/) {
    return 0;
}

int64_t DynamicHash::hashPcodeOp(void* /*op*/, HighFunction* /*hf*/) {
    return 0;
}

} // namespace ghidra
