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
/// \file AddressRangeImpl.cpp
/// \brief Concrete implementation of AddressRange
#include "ghidra/AddressRangeImpl.h"
#include <utility>

namespace ghidra {

AddressRangeImpl::AddressRangeImpl()
    : AddressRange() {}

AddressRangeImpl::AddressRangeImpl(const AddressRange& range)
    : AddressRange(range.getMinAddress(), range.getMaxAddress()) {}

AddressRangeImpl::AddressRangeImpl(const Address& start, const Address& end)
    : AddressRange(start < end ? start : end, start < end ? end : start) {
    AddressRange::checkValidRange(minAddr_, maxAddr_);
}

AddressRangeImpl::AddressRangeImpl(const Address& start, int64_t length)
    : AddressRange(start, start.addNoWrap(length - 1)) {}

int64_t AddressRangeImpl::getLength() const {
    return maxAddr_.getOffset() - minAddr_.getOffset() + 1;
}

uint64_t AddressRangeImpl::getBigLength() const {
    return static_cast<uint64_t>(maxAddr_.getOffset()) - static_cast<uint64_t>(minAddr_.getOffset()) + 1;
}

bool AddressRangeImpl::contains(const Address& addr) const {
    return minAddr_.hasSameAddressSpace(addr) &&
           addr >= minAddr_ && addr <= maxAddr_;
}

bool AddressRangeImpl::intersects(const AddressRange& range) const {
    return intersects(range.getMinAddress(), range.getMaxAddress());
}

bool AddressRangeImpl::intersects(const Address& start, const Address& end) const {
    if (!minAddr_.hasSameAddressSpace(start)) return false;
    return (end >= minAddr_) && (start <= maxAddr_);
}

AddressRange* AddressRangeImpl::intersect(const AddressRange& range) const {
    return intersectRange(range.getMinAddress(), range.getMaxAddress());
}

AddressRange* AddressRangeImpl::intersectRange(const Address& start, const Address& end) const {
    Address s = start, e = end;
    if (s > e) { std::swap(s, e); }
    Address min = (minAddr_ >= s) ? minAddr_ : s;
    Address max = (maxAddr_ <= e) ? maxAddr_ : e;
    if (min <= max) {
        return new AddressRangeImpl(min, max);
    }
    return nullptr;
}

int AddressRangeImpl::compareTo(const Address& addr) const {
    if (maxAddr_ < addr) return -1;
    if (minAddr_ > addr) return 1;
    return 0;
}

int AddressRangeImpl::compareTo(const AddressRange& other) const {
    int result = (minAddr_ < other.getMinAddress()) ? -1 :
                 (other.getMinAddress() < minAddr_) ? 1 : 0;
    if (result == 0) {
        result = (maxAddr_ < other.getMaxAddress()) ? -1 :
                 (other.getMaxAddress() < maxAddr_) ? 1 : 0;
    }
    return result;
}

const Address& AddressRangeImpl::getMaxAddress() const { return maxAddr_; }
const Address& AddressRangeImpl::getMinAddress() const { return minAddr_; }
AddressSpace* AddressRangeImpl::getAddressSpace() const { return minAddr_.getAddressSpace(); }

bool AddressRangeImpl::operator==(const AddressRangeImpl& other) const {
    return minAddr_ == other.minAddr_ && maxAddr_ == other.maxAddr_;
}

bool AddressRangeImpl::operator!=(const AddressRangeImpl& other) const { return !(*this == other); }

bool AddressRangeImpl::operator<(const AddressRangeImpl& other) const { return compareTo(other) < 0; }
bool AddressRangeImpl::operator>(const AddressRangeImpl& other) const { return compareTo(other) > 0; }

std::string AddressRangeImpl::toString() const {
    return "[" + minAddr_.toString() + ", " + maxAddr_.toString() + "]";
}

} // namespace ghidra
