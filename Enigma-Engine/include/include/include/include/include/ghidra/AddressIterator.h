/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AddressIterator.h
/// \brief Iterator for addresses
/// Translated from: ghidra.program.model.address.AddressIterator
#pragma once

#include <ghidra/Address.h>
#include <vector>
#include <cstddef>

namespace ghidra {

class AddressIterator {
public:
    AddressIterator();
    explicit AddressIterator(const std::vector<Address>& addresses);

    virtual ~AddressIterator() = default;

    virtual bool hasNext() const;
    virtual Address next();
    virtual Address current() const;
    virtual void reset();
    virtual size_t remaining() const;

protected:
    std::vector<Address> addresses_;
    size_t index_ = 0;
};

} // namespace ghidra
