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
/// \file ClosedException.h
/// \brief Exception indicating that the underlying resource has been closed
/// Translated from: ghidra.util.exception.ClosedException
#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

class ClosedException : public std::runtime_error {
private:
    std::string resourceName;

public:
    ClosedException() : std::runtime_error("File is closed"), resourceName() {}

    explicit ClosedException(const std::string& resourceName)
        : std::runtime_error(resourceName + " is closed"), resourceName(resourceName) {}

    const std::string& getResourceName() const { return resourceName; }
};

} // namespace ghidra
