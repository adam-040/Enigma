/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Address.cpp
/// \brief Address implementation - a location in a program (space + offset)
#include "ghidra/Address.h"
#include "ghidra/Decoder.h"
#include "ghidra/Encoder.h"
#include "ghidra/AttributeId.h"

namespace ghidra {

// Static NO_ADDRESS constant
const Address Address::NO_ADDRESS = Address("NO_ADDRESS");

// Static factory for special addresses
Address Address::createSpecial(const std::string& name) {
    return Address(name);
}

// Private constructor for special addresses
Address::Address(const std::string& name)
    : space_(nullptr), offset_(0), special_(true), specialName_(name) {}

// Construct an address in the given space with the given offset
Address::Address(AddressSpace* space, int64_t offset)
    : space_(space), offset_(space ? space->makeValidOffset(offset) : offset),
      special_(false) {}

// Default constructor (invalid address)
Address::Address() : space_(nullptr), offset_(0), special_(true), specialName_("NO ADDRESS") {}

// Get the offset as unsigned
uint64_t Address::getUnsignedOffset() const {
    if (!space_) return static_cast<uint64_t>(offset_);
    if (offset_ >= 0 || !space_->hasSignedOffset()) {
        return static_cast<uint64_t>(offset_);
    }
    int size = space_->getSize();
    if (size == 64) return static_cast<uint64_t>(offset_);
    int64_t spaceSize = static_cast<int64_t>(space_->getAddressableUnitSize()) << size;
    return static_cast<uint64_t>(spaceSize + offset_);
}

// Get addressable word offset
int64_t Address::getAddressableWordOffset() const {
    return space_ ? space_->getAddressableWordOffset(offset_) : offset_;
}

bool Address::hasSameAddressSpace(const Address& other) const {
    if (!space_ || !other.space_) return space_ == other.space_;
    return *space_ == *other.space_;
}

// Add displacement (wrapping)
Address Address::addWrap(int64_t displacement) const {
    if (displacement == 0 || !space_) return *this;
    return Address(space_, space_->truncateOffset(offset_ + displacement));
}

// Subtract displacement (wrapping)
Address Address::subtractWrap(int64_t displacement) const {
    return addWrap(-displacement);
}

// Add displacement (no wrap, throws on overflow, matching Ghidra Java semantics)
Address Address::addNoWrap(int64_t displacement) const {
    if (displacement == 0 || !space_) return *this;
    int64_t result = offset_ + displacement;
    bool overflow = false;
    if (displacement > 0) {
        if (result < offset_) overflow = true;
        else if (result > space_->getMaxOffset()) overflow = true;
    } else {
        if (result > offset_) overflow = true;
        else if (result < space_->getMinOffset()) overflow = true;
    }
    if (overflow) {
        throw std::overflow_error("Address overflow");
    }
    return Address(space_, result);
}

// Add displacement (general)
Address Address::add(int64_t displacement) const {
    return addWrap(displacement);
}

// Subtract displacement (general)
Address Address::subtract(int64_t displacement) const {
    return addWrap(-displacement);
}

// Compute displacement between addresses
int64_t Address::subtract(const Address& other) const {
    return offset_ - other.offset_;
}

// Next address (returns invalid if at max, matching Ghidra Java semantics)
Address Address::next() const {
    if (!space_) return Address();
    if (offset_ == space_->getMaxOffset()) return Address();
    return Address(space_, offset_ + 1);
}

// Previous address (returns invalid if at min, matching Ghidra Java semantics)
Address Address::previous() const {
    if (!space_) return Address();
    if (offset_ == space_->getMinOffset()) return Address();
    return Address(space_, offset_ - 1);
}

// Get successor check
bool Address::isSuccessor(const Address& other) const {
    if (!hasSameAddressSpace(other)) return false;
    return other.offset_ == offset_ + 1;
}

// String representation (default)
std::string Address::toString() const {
    if (special_) return specialName_;
    return toString(space_ ? space_->showSpaceName() : false, 8);
}

// String representation with options
std::string Address::toString(bool showSpace, int minDigits) const {
    if (special_) return specialName_;

    std::ostringstream buf;
    if (space_ && space_->isStackSpace()) {
        buf << "Stack[";
        int64_t disp = offset_;
        if (disp < 0) { buf << "-"; disp = -disp; }
        buf << "0x" << std::hex << disp << "]";
        return buf.str();
    }

    if (showSpace && space_) {
        buf << space_->getName() << ":";
    }

    int maxDigits = space_ ? ((space_->getSize() - 1) / 4 + 1) : 16;
    int padSize = std::min(minDigits, maxDigits);

    std::ostringstream hexBuf;
    hexBuf << std::hex << static_cast<uint64_t>(offset_);
    std::string hexStr = hexBuf.str();

    int zeros = std::max(0, padSize - static_cast<int>(hexStr.length()));
    for (int i = 0; i < zeros; i++) buf << '0';
    buf << hexStr;

    return buf.str();
}

// Comparison operators
bool Address::operator==(const Address& other) const {
    if (special_ || other.special_) {
        return special_ == other.special_ && specialName_ == other.specialName_;
    }
    if (space_ == other.space_) {
        return offset_ == other.offset_;
    }
    return space_ && other.space_ && *space_ == *other.space_ && offset_ == other.offset_;
}

bool Address::operator<(const Address& other) const {
    if (space_ != other.space_) {
        if (!space_) return true;
        if (!other.space_) return false;
        if (!(*space_ == *other.space_)) {
            return space_->getSpaceID() < other.space_->getSpaceID();
        }
    }
    if (space_ && space_->hasSignedOffset()) {
        return offset_ < other.offset_;
    }
    return static_cast<uint64_t>(offset_) < static_cast<uint64_t>(other.offset_);
}

std::size_t Address::hash() const {
    if (special_) return std::hash<std::string>{}(specialName_);
    int h1 = space_ ? space_->getSpaceID() : 0;
    int h3 = static_cast<int>(offset_ >> 32) ^ static_cast<int>(offset_);
    return static_cast<std::size_t>((h1 << 16) ^ h3);
}

// Get physical address
Address Address::getPhysicalAddress() const {
    if (!space_) return *this;
    AddressSpace* physical = space_->getPhysicalSpace();
    if (physical == space_) return *this;
    return Address(physical, offset_);
}

// Static min/max
const Address& Address::min(const Address& a, const Address& b) {
    return (a <= b) ? a : b;
}

const Address& Address::max(const Address& a, const Address& b) {
    return (a > b) ? a : b;
}

Address Address::decodeFromAttributes(Decoder& decoder) {
    std::string spaceName;
    int64_t offset = 0;
    int size = 0;
    for (;;) {
        int attribId = decoder.getNextAttributeId();
        if (attribId == 0) break;
        if (attribId == ATTRIB_NAME.id) {
            spaceName = decoder.readString();
        } else if (attribId == ATTRIB_OFFSET.id) {
            offset = static_cast<int64_t>(decoder.readUnsignedInteger());
        } else if (attribId == ATTRIB_SIZE.id) {
            size = static_cast<int>(decoder.readUnsignedInteger());
        } else {
            (void)decoder.readString();
        }
    }
    (void)size;
    return Address(nullptr, offset);
}

void Address::encodeAttributes(Encoder& encoder, const Address& addr) {
    encoder.writeUnsignedInteger(ATTRIB_OFFSET, static_cast<uint64_t>(addr.getOffset()));
}

void Address::encode(Encoder& encoder, const Address& addr) {
    encoder.openElement(ELEM_ADDR);
    encodeAttributes(encoder, addr);
    encoder.closeElement(ELEM_ADDR);
}

} // namespace ghidra
