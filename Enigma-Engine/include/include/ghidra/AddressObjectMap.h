/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AddressObjectMap.h
/// \brief Mapping between addresses and associated objects
/// Translated from: ghidra.program.model.address.AddressObjectMap
#pragma once

#include <ghidra/Address.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/AddressMapImpl.h>
#include <vector>
#include <unordered_map>

namespace ghidra {

class AddressObjectMap {
public:
    AddressObjectMap();

    std::vector<void*> getObjects(const Address& addr) const;
    void addObject(void* obj, const AddressSetView& set);
    void addObject(void* obj, const Address& startAddr, const Address& endAddr);
    void removeObject(void* obj, const AddressSetView& set);
    void removeObject(void* obj, const Address& startAddr, const Address& endAddr);

private:
    AddressMapImpl addrMap_;
    std::unordered_map<int64_t, std::vector<void*>> markers_;
};

} // namespace ghidra
