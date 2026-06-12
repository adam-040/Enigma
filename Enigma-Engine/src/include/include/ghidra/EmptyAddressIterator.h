/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file EmptyAddressIterator.h
/// \brief Empty AddressIterator implementation
/// Translated from: ghidra.program.model.address.EmptyAddressIterator
#pragma once

#include <ghidra/AddressIterator.h>

namespace ghidra {

class EmptyAddressIterator : public AddressIterator {
public:
    EmptyAddressIterator();

    bool hasNext() const override;
    Address next() override;
    Address current() const override;
    void reset() override;
    size_t remaining() const override;

    static EmptyAddressIterator& instance();
};

} // namespace ghidra
