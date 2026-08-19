/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file RegisterValue.h
/// \brief Register value storage
#pragma once

#include <ghidra/Register.h>
#include <vector>
#include <cstdint>

namespace ghidra {

class RegisterValue {
public:
    RegisterValue();
    RegisterValue(Register* reg, const std::vector<uint8_t>& value);
    RegisterValue(Register* reg, const std::vector<uint8_t>& value,
                  const std::vector<uint8_t>& mask);
    RegisterValue(Register* reg, uint64_t value, int size);

    Register* getRegister() const { return reg_; }
    const std::vector<uint8_t>& getValue() const { return value_; }

    /** Bit validity mask (same byte order as the value); empty when unset. */
    const std::vector<uint8_t>& getMask() const { return mask_; }

    uint64_t getUnsignedOffset() const;
    int64_t getSignedOffset() const;
    bool isBigEndian() const { return bigEndian_; }
    void setBigEndian(bool be) { bigEndian_ = be; }

private:
    Register* reg_ = nullptr;
    std::vector<uint8_t> value_;
    std::vector<uint8_t> mask_;
    bool bigEndian_ = false;
};

} // namespace ghidra
