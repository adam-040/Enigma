/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AddressIteratorAdapter.h
/// \brief Adapter wrapping an iterator of addresses to AddressIterator
/// Translated from: ghidra.program.model.address.AddressIteratorAdapter
#pragma once

#include <ghidra/AddressIterator.h>
#include <vector>
#include <cstddef>

namespace ghidra {

class AddressIteratorAdapter : public AddressIterator {
public:
    explicit AddressIteratorAdapter(const std::vector<Address>& addresses);
    explicit AddressIteratorAdapter(std::vector<Address>&& addresses);

    bool hasNext() const override;
    Address next() override;
    Address current() const override;
    void reset() override;
    size_t remaining() const override;
};

} // namespace ghidra
