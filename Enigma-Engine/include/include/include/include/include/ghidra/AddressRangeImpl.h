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
/// \file AddressRangeImpl.h
/// \brief Concrete implementation of AddressRange (immutable)
/// Translated from: ghidra.program.model.address.AddressRangeImpl
#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include "ghidra/AddressRange.h"

namespace ghidra {

class AddressRangeImpl : public AddressRange {
public:
    AddressRangeImpl();
    explicit AddressRangeImpl(const AddressRange& range);
    AddressRangeImpl(const Address& start, const Address& end);
    AddressRangeImpl(const Address& start, int64_t length);

    int64_t getLength() const override;
    uint64_t getBigLength() const override;

    bool contains(const Address& addr) const override;

    bool intersects(const AddressRange& range) const override;
    bool intersects(const Address& start, const Address& end) const override;

    AddressRange* intersect(const AddressRange& range) const override;
    AddressRange* intersectRange(const Address& start, const Address& end) const override;

    int compareTo(const Address& addr) const override;
    int compareTo(const AddressRange& other) const override;

    const Address& getMaxAddress() const override;
    const Address& getMinAddress() const override;
    AddressSpace* getAddressSpace() const override;

    bool operator==(const AddressRangeImpl& other) const;
    bool operator!=(const AddressRangeImpl& other) const;
    bool operator<(const AddressRangeImpl& other) const;
    bool operator>(const AddressRangeImpl& other) const;

    std::string toString() const override;
};

} // namespace ghidra
