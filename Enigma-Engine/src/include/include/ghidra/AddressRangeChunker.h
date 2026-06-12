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
#include <stdexcept>
#include <iterator>
#include <algorithm>

namespace ghidra {

class AddressRangeChunker {
private:
    Address end_;
    Address nextStartAddress_;
    uint64_t chunkSizeUnsigned_;

public:
    AddressRangeChunker(const AddressRange& range, uint64_t chunkSizeUnsigned)
        : AddressRangeChunker(range.getMinAddress(), range.getMaxAddress(), chunkSizeUnsigned) {}

    AddressRangeChunker(const Address& start, const Address& end, uint64_t chunkSizeUnsigned) {
        if (!start.isValid()) {
            throw std::invalid_argument("Start address cannot be null/invalid");
        }
        if (!end.isValid()) {
            throw std::invalid_argument("End address cannot be null/invalid");
        }
        if (start > end) {
            throw std::invalid_argument("Start address cannot be greater than end address");
        }
        if (!start.hasSameAddressSpace(end)) {
            throw std::invalid_argument("Addresses must be in the same address space");
        }
        if (chunkSizeUnsigned == 0) {
            throw std::invalid_argument("Chunk size must be greater than 0");
        }
        end_ = end;
        nextStartAddress_ = start;
        chunkSizeUnsigned_ = chunkSizeUnsigned;
    }

    class Iterator {
    private:
        Address end_;
        Address nextStartAddress_;
        uint64_t chunkSizeUnsigned_;
        AddressRange currentRange_;
        bool hasCurrent_ = false;

        void advance() {
            if (!nextStartAddress_.isValid()) {
                hasCurrent_ = false;
                return;
            }
            uint64_t availableLess1 = static_cast<uint64_t>(end_.subtract(nextStartAddress_));
            uint64_t sizeLess1 = std::min(chunkSizeUnsigned_ - 1, availableLess1);

            Address currentStart = nextStartAddress_;
            Address currentEnd = nextStartAddress_.addWrap(sizeLess1);
            if (currentEnd == end_) {
                nextStartAddress_ = Address(); // mark end
            } else {
                nextStartAddress_ = currentEnd.add(1);
            }
            currentRange_ = AddressRange(currentStart, currentEnd);
            hasCurrent_ = true;
        }

    public:
        using iterator_category = std::input_iterator_tag;
        using value_type = AddressRange;
        using difference_type = std::ptrdiff_t;
        using pointer = const AddressRange*;
        using reference = const AddressRange&;

        Iterator() : hasCurrent_(false) {} // Represents end
        Iterator(const Address& start, const Address& end, uint64_t chunkSize)
            : end_(end), nextStartAddress_(start), chunkSizeUnsigned_(chunkSize) {
            advance();
        }

        reference operator*() const { return currentRange_; }
        pointer operator->() const { return &currentRange_; }

        Iterator& operator++() {
            advance();
            return *this;
        }

        Iterator operator++(int) {
            Iterator tmp = *this;
            advance();
            return tmp;
        }

        bool operator==(const Iterator& other) const {
            if (!hasCurrent_ && !other.hasCurrent_) return true;
            if (hasCurrent_ != other.hasCurrent_) return false;
            return nextStartAddress_ == other.nextStartAddress_;
        }

        bool operator!=(const Iterator& other) const {
            return !(*this == other);
        }
    };

    Iterator begin() const {
        return Iterator(nextStartAddress_, end_, chunkSizeUnsigned_);
    }

    Iterator end() const {
        return Iterator();
    }
};

} // namespace ghidra
