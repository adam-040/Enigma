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
/// \file UnionAddressRangeIterator.h
/// \brief Iterator that merges two sorted AddressRangeIterators into a unified, non-overlapping sequence
/// Translated from: ghidra.util.UnionAddressRangeIterator
#pragma once

#include <ghidra/AddressRangeIterator.h>
#include <ghidra/AddressRangeImpl.h>

namespace ghidra {

/// \brief An iterator that produces the union of two sorted AddressRangeIterator streams.
///
/// Both input iterators must produce ranges in ascending order. The output
/// iterator produces non-overlapping, non-adjacent ranges covering every
/// address present in either input.
class UnionAddressRangeIterator : public AddressRangeIterator {
private:
    AddressRangeIterator* iter1_;
    AddressRangeIterator* iter2_;
    bool ownsIterators_;

    // Peek buffers
    bool has1_;
    bool has2_;
    AddressRangeImpl peek1_;
    AddressRangeImpl peek2_;

    // Precomputed next merged result
    bool nextReady_;
    AddressRangeImpl nextResult_;

    void loadPeek1();
    void loadPeek2();
    void computeNext();

public:
    /// \param iter1 First sorted range iterator
    /// \param iter2 Second sorted range iterator
    /// \param ownsIterators If true, this iterator will delete both input iterators on destruction
    UnionAddressRangeIterator(AddressRangeIterator* iter1, AddressRangeIterator* iter2,
                              bool ownsIterators = false);
    ~UnionAddressRangeIterator() override;

    bool hasNext() const override;
    const AddressRange& next() override;
};

} // namespace ghidra
