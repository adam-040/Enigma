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
/// \file RollbackException.h
/// \brief Exception thrown when a transaction should be rolled back
/// Translated from: ghidra.util.exception.RollbackException
#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

class RollbackException : public std::runtime_error {
public:
    explicit RollbackException(const std::string& message) : std::runtime_error(message) {}

    RollbackException(const std::string& message, const std::exception& cause)
        : std::runtime_error(message + " (caused by: " + std::string(cause.what()) + ")") {}
};

} // namespace ghidra
