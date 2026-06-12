/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file BitFieldPackingImpl.h
/// \brief Concrete bitfield packing policy.
#pragma once

#include "BitFieldPacking.h"

namespace ghidra {

class BitFieldPackingImpl : public BitFieldPacking {
public:
    static constexpr bool DEFAULT_USE_MS_CONVENTION = false;
    static constexpr bool DEFAULT_TYPE_ALIGNMENT_ENABLED = true;
    static constexpr int DEFAULT_ZERO_LENGTH_BOUNDARY = 0;

private:
    bool useMSConvention_ = DEFAULT_USE_MS_CONVENTION;
    bool typeAlignmentEnabled_ = DEFAULT_TYPE_ALIGNMENT_ENABLED;
    int zeroLengthBoundary_ = DEFAULT_ZERO_LENGTH_BOUNDARY;

public:
    bool useMSConvention() const override;

    bool isTypeAlignmentEnabled() const override;

    int getZeroLengthBoundary() const override;

    void setUseMSConvention(bool useMSConvention);

    void setTypeAlignmentEnabled(bool typeAlignmentEnabled);

    void setZeroLengthBoundary(int zeroLengthBoundary);
};

} // namespace ghidra
