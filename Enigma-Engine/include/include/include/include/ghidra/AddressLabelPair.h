/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AddressLabelPair.h
/// \brief Container for holding an address and label.
/// Translated from: ghidra.program.model.symbol.AddressLabelPair
#pragma once

#include <ghidra/Address.h>
#include <string>

namespace ghidra {

class AddressLabelPair {
public:
    AddressLabelPair() = default;
    AddressLabelPair(const Address& addr, const std::string& label)
        : addr_(addr), label_(label) {}

    const Address& getAddress() const { return addr_; }
    const std::string& getLabel() const { return label_; }

    bool equals(const AddressLabelPair& other) const {
        return addr_ == other.addr_ && label_ == other.label_;
    }

    bool operator==(const AddressLabelPair& other) const {
        return addr_ == other.addr_ && label_ == other.label_;
    }
    bool operator!=(const AddressLabelPair& other) const {
        return !(*this == other);
    }

private:
    Address addr_;
    std::string label_;
};

} // namespace ghidra
