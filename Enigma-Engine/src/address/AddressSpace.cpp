/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AddressSpace.cpp
/// \brief GenericAddressSpace implementation
#include "ghidra/AddressSpace.h"
#include "ghidra/Address.h"
#include "ghidra/AddressFormatException.h"
#include <cstdint>
#include <cstdlib>
#include <stdexcept>

namespace ghidra {

AddressSpace::~AddressSpace() = default;

static int64_t parseHexOrDecimal(const std::string& s) {
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        return static_cast<int64_t>(std::stoull(s.substr(2), nullptr, 16));
    }
    return static_cast<int64_t>(std::stoull(s, nullptr, 10));
}

Address AddressSpace::getAddress(int64_t byteOffset) const {
    return Address(const_cast<AddressSpace*>(this), byteOffset);
}

Address AddressSpace::getAddressInThisSpaceOnly(int64_t byteOffset) const {
    return Address(const_cast<AddressSpace*>(this), byteOffset);
}

Address AddressSpace::getAddress(const std::string& addrString, bool /*caseSensitive*/) const {
    if (addrString.empty()) {
        throw AddressFormatException("Empty address string");
    }
    try {
        int64_t off = parseHexOrDecimal(addrString);
        return Address(const_cast<AddressSpace*>(this), off);
    } catch (const std::exception& e) {
        throw AddressFormatException(std::string("Cannot parse address: ") + e.what());
    }
}

GenericAddressSpace::GenericAddressSpace(const std::string& name, int size, int type, int unique)
    : name_(name), size_(size), type_(type), unique_(unique),
      unitSize_(1), offsetMask_(size == 64 ? ~0ULL : ((1ULL << size) - 1)),
      signed_(type == TYPE_CONSTANT || type == TYPE_STACK) {

    int sizeEncoded = ((size > 0 ? (size - 1) / 8 : 0) << ID_SIZE_SHIFT) & ID_SIZE_MASK;
    spaceID_ = (type & ID_TYPE_MASK) | sizeEncoded | (unique << ID_UNIQUE_SHIFT);

    if (size == 64) {
        maxOffset_ = -1LL;
        minOffset_ = 0;
    } else {
        maxOffset_ = (1LL << size) - 1;
        minOffset_ = 0;
    }

    if (signed_) {
        if (size == 64) {
            minOffset_ = static_cast<int64_t>(0x8000000000000000ULL);
            maxOffset_ = 0x7FFFFFFFFFFFFFFFLL;
        } else {
            minOffset_ = -(1LL << (size - 1));
            maxOffset_ = (1LL << (size - 1)) - 1;
        }
    }
}

std::string GenericAddressSpace::getName() const { return name_; }
int GenericAddressSpace::getSpaceID() const { return spaceID_; }
int GenericAddressSpace::getSize() const { return size_; }
int GenericAddressSpace::getAddressableUnitSize() const { return unitSize_; }

int64_t GenericAddressSpace::getAddressableWordOffset(int64_t byteOffset) const {
    return byteOffset / unitSize_;
}

int GenericAddressSpace::getPointerSize() const { return (size_ + 7) / 8; }
int GenericAddressSpace::getType() const { return type_; }
int GenericAddressSpace::getUnique() const { return unique_; }

int64_t GenericAddressSpace::truncateOffset(int64_t byteOffset) const {
    if (size_ >= 64) return byteOffset;
    return static_cast<int64_t>(static_cast<uint64_t>(byteOffset) & offsetMask_);
}

int64_t GenericAddressSpace::truncateAddressableWordOffset(int64_t wordOffset) const {
    return truncateOffset(wordOffset);
}

int64_t GenericAddressSpace::makeValidOffset(int64_t offset) const {
    if (size_ >= 64) return offset;

    int64_t truncated = truncateOffset(offset);
    if (!signed_ || size_ <= 0) {
        return truncated;
    }

    const uint64_t signBit = 1ULL << (size_ - 1);
    uint64_t value = static_cast<uint64_t>(truncated) & offsetMask_;
    if ((value & signBit) != 0) {
        value |= ~offsetMask_;
    }
    return static_cast<int64_t>(value);
}

int64_t GenericAddressSpace::getMaxOffset() const { return maxOffset_; }
int64_t GenericAddressSpace::getMinOffset() const { return minOffset_; }

bool GenericAddressSpace::isMemorySpace() const {
    return type_ == TYPE_RAM || type_ == TYPE_CODE || type_ == TYPE_OTHER;
}

bool GenericAddressSpace::isLoadedMemorySpace() const {
    return type_ == TYPE_RAM || type_ == TYPE_CODE;
}

bool GenericAddressSpace::isNonLoadedMemorySpace() const { return type_ == TYPE_OTHER; }
bool GenericAddressSpace::isRegisterSpace() const { return type_ == TYPE_REGISTER; }
bool GenericAddressSpace::isVariableSpace() const { return type_ == TYPE_VARIABLE; }
bool GenericAddressSpace::isStackSpace() const { return type_ == TYPE_STACK; }
bool GenericAddressSpace::isHashSpace() const { return type_ == TYPE_UNKNOWN; }
bool GenericAddressSpace::isExternalSpace() const { return type_ == TYPE_EXTERNAL; }
bool GenericAddressSpace::isUniqueSpace() const { return type_ == TYPE_UNIQUE; }
bool GenericAddressSpace::isConstantSpace() const { return type_ == TYPE_CONSTANT; }
bool GenericAddressSpace::hasMappedRegisters() const { return false; }
bool GenericAddressSpace::showSpaceName() const { return type_ != TYPE_RAM; }
bool GenericAddressSpace::isOverlaySpace() const { return false; }
bool GenericAddressSpace::hasSignedOffset() const { return signed_; }

AddressSpace* GenericAddressSpace::getPhysicalSpace() { return this; }

Address GenericAddressSpace::getAddress(int64_t byteOffset) const {
    return Address(const_cast<GenericAddressSpace*>(this), byteOffset);
}

Address GenericAddressSpace::getAddressInThisSpaceOnly(int64_t byteOffset) const {
    return getAddress(byteOffset);
}

Address GenericAddressSpace::getAddress(const std::string& addrString, bool caseSensitive) const {
    return AddressSpace::getAddress(addrString, caseSensitive);
}

} // namespace ghidra
