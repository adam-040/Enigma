/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once

#include <ghidra/Address.h>
#include <ghidra/AddressRange.h>
#include <ghidra/AddressRangeImpl.h>
#include <ghidra/AddressOverflowException.h>
#include <string>
#include <algorithm>

namespace ghidra {

class SourceFile;

class SourceMapEntry {
public:
    SourceMapEntry() = default;
    SourceMapEntry(SourceFile* sourceFile, int lineNumber, const Address& baseAddress, uint64_t length)
        : sourceFile_(sourceFile), lineNumber_(lineNumber), baseAddress_(baseAddress), length_(length) {
        if (length_ > 0) {
            Address maxAddr;
            try {
                maxAddr = baseAddress_.addNoWrap(length_ - 1);
            } catch (const AddressOverflowException&) {
                auto genSpace = dynamic_cast<const GenericAddressSpace*>(baseAddress_.getAddressSpace());
                uint64_t maxOffset = genSpace ? genSpace->getMaxOffset() : (baseAddress_.getAddressSpace()->getSize() == 64 ? -1LL : ((1ULL << baseAddress_.getAddressSpace()->getSize()) - 1));
                maxAddr = Address(baseAddress_.getAddressSpace(), maxOffset);
            }
            range_ = AddressRangeImpl(baseAddress_, maxAddr);
            hasRange_ = true;
        }
    }

    int getLineNumber() const { return lineNumber_; }
    SourceFile* getSourceFile() const { return sourceFile_; }
    const Address& getBaseAddress() const { return baseAddress_; }
    uint64_t getLength() const { return length_; }
    
    bool hasRange() const { return hasRange_; }
    AddressRange getRange() const { return range_; }

    bool operator==(const SourceMapEntry& other) const {
        if (lineNumber_ != other.lineNumber_ || sourceFile_ != other.sourceFile_ ||
            baseAddress_ != other.baseAddress_ || length_ != other.length_ ||
            hasRange_ != other.hasRange_) {
            return false;
        }
        if (hasRange_) {
            return range_.getMinAddress() == other.range_.getMinAddress() &&
                   range_.getMaxAddress() == other.range_.getMaxAddress();
        }
        return true;
    }

    bool operator!=(const SourceMapEntry& other) const {
        return !(*this == other);
    }

    int compareTo(const SourceMapEntry& other) const;
    bool operator<(const SourceMapEntry& other) const {
        return compareTo(other) < 0;
    }

private:
    SourceFile* sourceFile_ = nullptr;
    int lineNumber_ = 0;
    Address baseAddress_;
    uint64_t length_ = 0;
    bool hasRange_ = false;
    AddressRangeImpl range_;
};

} // namespace ghidra
