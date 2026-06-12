/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AddressSetMapping.h
/// \brief Index-based random access to addresses in an AddressSet
/// Translated from: ghidra.program.model.address.AddressSetMapping
#pragma once

#include <ghidra/AddressSetView.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AddressRange.h>
#include <vector>
#include <cstdint>

namespace ghidra {

class AddressSetMapping {
public:
    explicit AddressSetMapping(const AddressSetView& set);

    Address getAddress(int index) const;

private:
    const AddressSetView* set_;
    std::vector<AddressRange> ranges_;
    std::vector<int64_t> indexes_;

    void buildRanges();
    void buildIndexes();
};

} // namespace ghidra
