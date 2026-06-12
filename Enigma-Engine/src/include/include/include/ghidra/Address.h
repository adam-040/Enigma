/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Address.h
/// \brief Address representation - a location in a program (space + offset)
#pragma once

#include <cstdint>
#include <string>
#include <sstream>
#include <iomanip>
#include <memory>
#include <functional>
#include <stdexcept>
#include "AddressSpace.h"

namespace ghidra {

class Decoder;
class Encoder;

class Address {
private:
    AddressSpace* space_;
    int64_t offset_;
    bool special_;
    std::string specialName_;

    Address(const std::string& name);

public:
    static constexpr char SEPARATOR_CHAR = ':';
    static const Address NO_ADDRESS;

    static Address createSpecial(const std::string& name);

    /// Decode an Address from the current XML element's attributes.
    /// Used by jump-table and symbol-entry codecs.
    static Address decodeFromAttributes(Decoder& decoder);
    /// Encode Address attributes into the current XML element.
    static void encodeAttributes(Encoder& encoder, const Address& addr);
    /// Open a new &lt;addr&gt; element and encode the address into it.
    static void encode(Encoder& encoder, const Address& addr);

    Address(AddressSpace* space, int64_t offset);
    Address();

    int64_t getOffset() const { return offset_; }
    uint64_t getUnsignedOffset() const;
    int64_t getAddressableWordOffset() const;
    AddressSpace* getAddressSpace() const { return space_; }
    int getSize() const { return space_ ? space_->getSize() : 0; }
    int getPointerSize() const { return space_ ? space_->getPointerSize() : 0; }
    bool isSpecial() const { return special_; }
    bool isValid() const { return space_ != nullptr; }
    bool isMemoryAddress() const { return space_ && space_->isMemorySpace(); }
    bool isLoadedMemoryAddress() const { return space_ && space_->isLoadedMemorySpace(); }
    bool isNonLoadedMemoryAddress() const { return space_ && space_->isNonLoadedMemorySpace(); }
    bool isStackAddress() const { return space_ && space_->isStackSpace(); }
    bool isUniqueAddress() const { return space_ && space_->isUniqueSpace(); }
    bool isConstantAddress() const { return space_ && space_->isConstantSpace(); }
    bool isHashAddress() const { return space_ && space_->isHashSpace(); }
    bool isRegisterAddress() const { return space_ && space_->isRegisterSpace(); }
    bool isVariableAddress() const { return space_ && space_->isVariableSpace(); }
    bool isExternalAddress() const { return space_ && space_->isExternalSpace(); }

    bool hasSameAddressSpace(const Address& other) const;

    Address addWrap(int64_t displacement) const;
    Address subtractWrap(int64_t displacement) const;
    Address addNoWrap(int64_t displacement) const;
    Address add(int64_t displacement) const;
    Address subtract(int64_t displacement) const;
    int64_t subtract(const Address& other) const;
    Address next() const;
    Address previous() const;
    bool isSuccessor(const Address& other) const;

    std::string toString() const;
    std::string toString(bool showSpace, int minDigits = 8) const;

    bool operator==(const Address& other) const;
    bool operator!=(const Address& other) const { return !(*this == other); }
    bool operator<(const Address& other) const;
    bool operator>(const Address& other) const { return other < *this; }
    bool operator<=(const Address& other) const { return !(other < *this); }
    bool operator>=(const Address& other) const { return !(*this < other); }

    int compareTo(const Address& other) const {
        if (*this < other) return -1;
        if (other < *this) return 1;
        return 0;
    }

    std::size_t hash() const;

    Address getPhysicalAddress() const;

    static const Address& min(const Address& a, const Address& b);
    static const Address& max(const Address& a, const Address& b);
};

} // namespace ghidra

namespace std {
    template<> struct hash<ghidra::Address> {
        std::size_t operator()(const ghidra::Address& a) const { return a.hash(); }
    };
}
