/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AddressMap.h
/// \brief Maps addresses between language and internal representations
/// Translated from: ghidra.program.database.map.AddressMap
#pragma once

#include <ghidra/Address.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/AddressSetView.h>
#include <unordered_map>
#include <string>
#include <optional>

namespace ghidra {

class AddressMap {
public:
    static constexpr int NO_ADDRESS_SPACE_INDEX = -1;

    virtual ~AddressMap() = default;

    virtual int getNumAddressSpaces() const = 0;
    virtual AddressSpace* getLanguageAddressSpace(int id) const = 0;
    virtual int getLanguageAddressSpaceID(const AddressSpace* space) const = 0;
    virtual Address mapLanguageAddress(const Address& langAddr) const = 0;
    virtual Address mapInternalAddress(const Address& internalAddr) const = 0;
    virtual int getOverlaySpaceCount() const = 0;
    virtual AddressSpace* getOverlaySpace(const std::string& name) const = 0;
    virtual AddressSpace* createOverlaySpace(const std::string& name, AddressSpace* baseSpace) = 0;
    virtual bool removeOverlaySpace(const std::string& name) = 0;
    virtual std::vector<std::string> getOverlaySpaceNames() const = 0;
    virtual bool hasOverlaySpaces() const = 0;
    virtual AddressSpace* getDefaultAddressSpace() const = 0;
};

} // namespace ghidra
