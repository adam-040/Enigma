/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file RelocationResult.cpp
/// \brief Status and byte-length of a processed relocation.
#include "ghidra/RelocationResult.h"

namespace ghidra {

const RelocationResult RelocationResult::FAILURE(Relocation::Status::FAILURE, 0);
const RelocationResult RelocationResult::UNSUPPORTED(Relocation::Status::UNSUPPORTED, 0);
const RelocationResult RelocationResult::SKIPPED(Relocation::Status::SKIPPED, 0);
const RelocationResult RelocationResult::PARTIAL(Relocation::Status::PARTIAL, 0);

} // namespace ghidra
