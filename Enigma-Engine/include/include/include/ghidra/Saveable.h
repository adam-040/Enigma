/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 */
/// \file Saveable.h
/// \brief Interface for objects that can be persisted
/// Translated from: ghidra.util.Saveable
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ghidra {

class Saveable {
public:
    virtual ~Saveable() = default;

    virtual int32_t getSchemaVersion() const = 0;
    virtual bool isUpgradeable(int32_t oldVersion) const = 0;
    virtual bool upgrade(int32_t oldVersion, int32_t& currentVersion) = 0;
    virtual bool save(std::vector<uint8_t>& buf) const = 0;
    virtual bool restore(const std::vector<uint8_t>& buf) = 0;
    virtual int32_t getStorageSize() const = 0;
    virtual std::string getDescription() const = 0;
};

} // namespace ghidra
