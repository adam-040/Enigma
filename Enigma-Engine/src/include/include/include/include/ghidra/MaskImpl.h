/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file MaskImpl.h
/// \brief Byte-array implementation of the Mask interface.
/// Translated from: ghidra.program.model.lang.MaskImpl
#pragma once

#include "ghidra/Mask.h"
#include "ghidra/MemBuffer.h"
#include <vector>
#include <cstdint>

namespace ghidra {

class MaskImpl : public Mask {
public:
    explicit MaskImpl(const std::vector<uint8_t>& msk);
    MaskImpl(const uint8_t* msk, size_t len);

    bool equals(const Mask* obj) const override;
    bool equals(const std::vector<uint8_t>& otherMask) const override;
    std::vector<uint8_t> applyMask(const std::vector<uint8_t>& cde, std::vector<uint8_t>& results) override;
    void applyMask(const std::vector<uint8_t>& cde, int cdeOffset,
                   std::vector<uint8_t>& results, int resultsOffset) override;
    std::vector<uint8_t> applyMask(MemBuffer* buffer) override;
    bool equalMaskedValue(const std::vector<uint8_t>& cde, const std::vector<uint8_t>& target) override;
    bool subMask(const std::vector<uint8_t>& msk) override;
    std::vector<uint8_t> complementMask(const std::vector<uint8_t>& msk, std::vector<uint8_t>& results) override;
    std::vector<uint8_t> getBytes() const override { return mask; }
    std::string toString() const;

private:
    std::vector<uint8_t> mask;
};

} // namespace ghidra
