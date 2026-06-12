/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file HighParamID.cpp
/// \brief High-level abstraction associated with a low level function for parameter measures.
#include "ghidra/pcode/HighParamID.h"
#include "ghidra/Decoder.h"

namespace ghidra {
namespace pcode {

HighParamID::HighParamID()
    : func(nullptr), protoextrapop(-1) {}

HighParamID::HighParamID(void* function, void* /*language*/, void* /*compilerSpec*/, void* /*dtManager*/)
    : func(function), protoextrapop(-1) {}

void HighParamID::decode(Decoder& /*decoder*/) {}

void HighParamID::storeReturnToDatabase(bool /*storeDataTypes*/, int /*sourceType*/) {}
void HighParamID::storeParametersToDatabase(bool /*storeDataTypes*/, int /*sourceType*/) {}

}  // namespace pcode
}  // namespace ghidra
