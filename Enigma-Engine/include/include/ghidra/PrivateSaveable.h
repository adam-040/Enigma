/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 */
/// \file PrivateSaveable.h
/// \brief Interface with private save/restore for factory-based deserialization
/// Translated from: ghidra.util.PrivateSaveable
#pragma once

#include "Saveable.h"
#include <cstdint>
#include <vector>

namespace ghidra {

class PrivateSaveable : public Saveable {
public:
    ~PrivateSaveable() override = default;

    virtual bool privateSave(std::vector<uint8_t>& buf) const = 0;
    virtual bool privateRestore(const std::vector<uint8_t>& buf, int32_t version) = 0;
};

} // namespace ghidra
