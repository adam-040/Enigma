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
/// \file DisposedException.h
/// \brief Exception thrown when an operation is attempted on a disposed object
/// Translated from: ghidra.async.DisposedException
#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

class DisposedException : public std::runtime_error {
public:
    DisposedException() : std::runtime_error("Object has been disposed") {}

    explicit DisposedException(const std::string& message) : std::runtime_error(message) {}

    DisposedException(const std::string& message, const std::exception& cause)
        : std::runtime_error(message + " (caused by: " + std::string(cause.what()) + ")") {}
};

} // namespace ghidra
