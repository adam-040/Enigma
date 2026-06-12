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
/// \file AccumulatorSizeException.h
/// \brief Exception thrown when accumulator maximum capacity is exceeded
/// Translated from: ghidra.util.datastruct.AccumulatorSizeException
#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

class AccumulatorSizeException : public std::runtime_error {
private:
    int maxSize;

public:
    explicit AccumulatorSizeException(int maxSize)
        : std::runtime_error("Maximum capacity exceeded: " + std::to_string(maxSize)),
          maxSize(maxSize) {}

    int getMaxSize() const { return maxSize; }
};

} // namespace ghidra
