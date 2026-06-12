/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Mask.h
/// \brief Performs basic bit tests on an array of bits
/// Translated from: ghidra.program.model.lang.Mask
#pragma once

#include <cstdint>
#include <vector>
#include "ghidra/MemBuffer.h"
#include "ghidra/MemoryAccessException.h"
#include "ghidra/IncompatibleMaskException.h"

namespace ghidra {

class Mask {
public:
    virtual ~Mask() = default;
    virtual bool equals(const Mask* obj) const = 0;
    virtual bool equals(const std::vector<uint8_t>& mask) const = 0;
    virtual std::vector<uint8_t> applyMask(const std::vector<uint8_t>& cde, std::vector<uint8_t>& results) = 0;
    virtual void applyMask(const std::vector<uint8_t>& cde, int cdeOffset,
                           std::vector<uint8_t>& results, int resultsOffset) = 0;
    virtual std::vector<uint8_t> applyMask(MemBuffer* buffer) = 0;
    virtual bool equalMaskedValue(const std::vector<uint8_t>& cde, const std::vector<uint8_t>& target) = 0;
    virtual std::vector<uint8_t> complementMask(const std::vector<uint8_t>& msk, std::vector<uint8_t>& results) = 0;
    virtual bool subMask(const std::vector<uint8_t>& msk) = 0;
    virtual std::vector<uint8_t> getBytes() const = 0;
};

} // namespace ghidra
