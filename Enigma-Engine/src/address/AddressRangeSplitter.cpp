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
/// \file AddressRangeSplitter.cpp
/// \brief Iterator that splits a single address range into smaller chunks
#include "ghidra/AddressRangeSplitter.h"

namespace ghidra {

AddressRangeSplitter::AddressRangeSplitter(const AddressRangeImpl& range, uint32_t splitSize, bool forward)
    : remainingRange_(range), splitSize_(splitSize), forward_(forward) {}

bool AddressRangeSplitter::hasNext() const {
    return remainingRange_.has_value();
}

std::optional<AddressRangeImpl> AddressRangeSplitter::next() {
    if (!remainingRange_.has_value()) {
        return std::nullopt;
    }
    if (isRangeSmallEnough()) {
        AddressRangeImpl returnValue = remainingRange_.value();
        remainingRange_.reset();
        return returnValue;
    }
    return forward_ ? extractChunkFromStart() : extractChunkFromEnd();
}

AddressRangeSplitter::iterator::iterator() : splitter_(nullptr) {}

AddressRangeSplitter::iterator::iterator(AddressRangeSplitter* splitter) : splitter_(splitter) { advance(); }

void AddressRangeSplitter::iterator::advance() {
    if (splitter_ && splitter_->hasNext()) {
        current_ = splitter_->next();
    } else {
        current_.reset();
        splitter_ = nullptr;
    }
}

const AddressRangeImpl& AddressRangeSplitter::iterator::operator*() const { return current_.value(); }
const AddressRangeImpl* AddressRangeSplitter::iterator::operator->() const { return &current_.value(); }

AddressRangeSplitter::iterator& AddressRangeSplitter::iterator::operator++() { advance(); return *this; }
AddressRangeSplitter::iterator AddressRangeSplitter::iterator::operator++(int) { iterator tmp = *this; advance(); return tmp; }

bool AddressRangeSplitter::iterator::operator==(const iterator& other) const {
    return (!splitter_ && !other.splitter_) ||
           (splitter_ == other.splitter_ && current_.has_value() == other.current_.has_value());
}
bool AddressRangeSplitter::iterator::operator!=(const iterator& other) const { return !(*this == other); }

AddressRangeSplitter::iterator AddressRangeSplitter::begin() { return iterator(this); }
AddressRangeSplitter::iterator AddressRangeSplitter::end() { return iterator(); }

AddressRangeImpl AddressRangeSplitter::extractChunkFromStart() {
    const Address& start = remainingRange_->getMinAddress();
    Address end = start.add(splitSize_ - 1);
    AddressRangeImpl chunk(start, end);
    remainingRange_ = AddressRangeImpl(end.next(), remainingRange_->getMaxAddress());
    return chunk;
}

AddressRangeImpl AddressRangeSplitter::extractChunkFromEnd() {
    const Address& end = remainingRange_->getMaxAddress();
    Address start = end.subtract(splitSize_ - 1);
    AddressRangeImpl chunk(start, end);
    remainingRange_ = AddressRangeImpl(remainingRange_->getMinAddress(), start.previous());
    return chunk;
}

bool AddressRangeSplitter::isRangeSmallEnough() const {
    return remainingRange_->getBigLength() <= splitSize_;
}

} // namespace ghidra
