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
/// \file AddressRangeIterator.h
/// \brief Iterator interface for AddressRange collections
/// Translated from: ghidra.program.model.address.AddressRangeIterator
#pragma once

#include <iterator>
#include "ghidra/AddressRange.h"

namespace ghidra {

class AddressRangeIterator {
public:
    virtual ~AddressRangeIterator();

    virtual bool hasNext() const = 0;
    virtual const AddressRange& next() = 0;

    bool hasMore() const { return hasNext(); }
};

} // namespace ghidra
