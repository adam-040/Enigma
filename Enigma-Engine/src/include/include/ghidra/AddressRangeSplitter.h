/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/// \file AddressRangeSplitter.h
/// \brief Iterator that splits a single address range into smaller chunks
/// Translated from: ghidra.program.model.address.AddressRangeSplitter
#pragma once

#include <optional>
#include <cstdint>
#include "ghidra/AddressRangeImpl.h"

namespace ghidra {

class AddressRangeSplitter {
private:
    std::optional<AddressRangeImpl> remainingRange_;
    uint32_t splitSize_;
    bool forward_;

public:
    AddressRangeSplitter(const AddressRangeImpl& range, uint32_t splitSize, bool forward = true);

    bool hasNext() const;
    std::optional<AddressRangeImpl> next();

    class iterator {
    private:
        AddressRangeSplitter* splitter_;
        std::optional<AddressRangeImpl> current_;

        void advance();

    public:
        using iterator_category = std::input_iterator_tag;
        using value_type = AddressRangeImpl;
        using difference_type = std::ptrdiff_t;
        using pointer = const AddressRangeImpl*;
        using reference = const AddressRangeImpl&;

        iterator();
        explicit iterator(AddressRangeSplitter* splitter);

        const AddressRangeImpl& operator*() const;
        const AddressRangeImpl* operator->() const;

        iterator& operator++();
        iterator operator++(int);

        bool operator==(const iterator& other) const;
        bool operator!=(const iterator& other) const;
    };

    iterator begin();
    iterator end();

private:
    AddressRangeImpl extractChunkFromStart();
    AddressRangeImpl extractChunkFromEnd();
    bool isRangeSmallEnough() const;
};

} // namespace ghidra
