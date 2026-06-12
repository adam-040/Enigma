/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file RelocationResult.h
/// \brief Status and byte-length of a processed relocation.
#pragma once

#include "ghidra/Relocation.h"

namespace ghidra {

class RelocationResult {
public:
    RelocationResult(Relocation::Status status, int byteLength)
        : status_(status), byteLength_(byteLength) {}

    Relocation::Status getStatus() const { return status_; }
    int getByteLength() const { return byteLength_; }

    static const RelocationResult FAILURE;
    static const RelocationResult UNSUPPORTED;
    static const RelocationResult SKIPPED;
    static const RelocationResult PARTIAL;

private:
    Relocation::Status status_;
    int byteLength_;
};

} // namespace ghidra
