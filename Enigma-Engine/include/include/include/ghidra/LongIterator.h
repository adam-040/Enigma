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
/// \file LongIterator.h
/// \brief Iterator over int64_t values
/// Translated from: ghidra.util.LongIterator
#pragma once

#include <cstdint>

namespace ghidra {

/// \brief Iterator over int64_t values with forward and backward traversal.
class LongIterator {
public:
    virtual ~LongIterator() = default;

    /// \brief Returns true if there is a next value.
    virtual bool hasNext() = 0;

    /// \brief Returns the next value.
    virtual int64_t next() = 0;

    /// \brief Returns true if there is a previous value.
    virtual bool hasPrevious() = 0;

    /// \brief Returns the previous value.
    virtual int64_t previous() = 0;

    /// \brief An empty LongIterator singleton.
    static LongIterator& EMPTY();
};

} // namespace ghidra
