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
/// \file TwoWayBreakdownAddressRangeIterator.h
/// \brief Iterator that breaks address ranges at boundary points and tags each fragment by source
/// Translated from: ghidra.util.TwoWayBreakdownAddressRangeIterator
#pragma once

#include <ghidra/AddressRangeIterator.h>
#include <ghidra/AddressRangeImpl.h>
#include <optional>
#include <utility>

namespace ghidra {

/// \brief An iterator that takes two sorted range iterators and breaks ranges at every
/// boundary point, producing fragments tagged with which source(s) they came from.
///
/// This is useful for comparing two address sets range-by-range, e.g., to determine
/// which regions are unique to set A, unique to set B, or shared by both.
class TwoWayBreakdownAddressRangeIterator : public AddressRangeIterator {
public:
    /// Indicates which source(s) a fragment came from
    enum class Which {
        LEFT,   ///< Fragment is only in the left (first) iterator
        RIGHT,  ///< Fragment is only in the right (second) iterator
        BOTH    ///< Fragment is in both iterators
    };

    /// A range fragment tagged with its source
    struct Entry {
        AddressRangeImpl range;
        Which which;
        Entry() : range(), which(Which::LEFT) {}
        Entry(const AddressRangeImpl& r, Which w) : range(r), which(w) {}
    };

private:
    AddressRangeIterator* leftIter_;
    AddressRangeIterator* rightIter_;
    bool ownsIterators_;

    // Peek buffers for left/right
    bool hasLeft_;
    bool hasRight_;
    AddressRangeImpl peekLeft_;
    AddressRangeImpl peekRight_;

    // Current output
    bool nextReady_;
    Entry nextEntry_;

    void loadLeft();
    void loadRight();
    void computeNext();

    /// Consume [start..end] from the left peek buffer, advancing if fully consumed
    void consumeLeft(const Address& throughAddr);
    /// Consume [start..end] from the right peek buffer, advancing if fully consumed
    void consumeRight(const Address& throughAddr);

public:
    /// \param left First sorted range iterator
    /// \param right Second sorted range iterator
    /// \param ownsIterators If true, this iterator will delete both input iterators on destruction
    TwoWayBreakdownAddressRangeIterator(AddressRangeIterator* left, AddressRangeIterator* right,
                                         bool ownsIterators = false);
    ~TwoWayBreakdownAddressRangeIterator() override;

    bool hasNext() const override;
    const AddressRange& next() override;

    /// \brief Get the current entry (range + source tag) after calling next()
    const Entry& getCurrentEntry() const { return nextEntry_; }

    /// \brief Check if there is a next entry and retrieve it
    bool hasNextEntry() const { return nextReady_; }
    Entry nextEntry();
};

} // namespace ghidra
