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
/// \file Accumulator.h
/// \brief Interface for collecting result data as it becomes available
/// Translated from: ghidra.util.datastruct.Accumulator
#pragma once

#include <vector>
#include <cstdint>

namespace ghidra {

/// \brief Interface for accumulating result data.
///
/// Provides a mechanism for passing around a 'results object' into which
/// data can be placed as it is discovered.
template<typename T>
class Accumulator {
public:
    virtual ~Accumulator() = default;

    /// \brief Add a single item.
    virtual void add(const T& t) = 0;

    /// \brief Add all items from a collection.
    virtual void addAll(const std::vector<T>& collection) = 0;

    /// \brief Returns the number of items added so far.
    virtual int32_t getProgress() const = 0;
};

} // namespace ghidra
