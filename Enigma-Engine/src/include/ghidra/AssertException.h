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
/// \file AssertException.h
/// \brief Exception used in situations that the programmer believes can't happen
#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

/**
 * AssertException is used in situations that the programmer believes can't happen.
 * If it does, then there is a programming error of some kind.
 * Translated from: ghidra.util.exception.AssertException
 * Java hierarchy: RuntimeException -> AssertException
 * C++ hierarchy: std::runtime_error -> AssertException
 */
class AssertException : public std::runtime_error {
public:
    /// Create a new AssertException with no message.
    AssertException()
        : std::runtime_error("Unexpected Error") {}

    /// Create a new AssertException with the given message.
    /// \param msg the exception message
    explicit AssertException(const std::string& msg)
        : std::runtime_error(msg) {}

    /// Create a new AssertException from another exception.
    /// The message for this exception will be derived from the exception.
    /// \param e the exception which caused this to be generated
    explicit AssertException(const std::exception& e)
        : std::runtime_error(std::string("Unexpected Error: ") + e.what()) {}

    /// Create a new AssertException with the given message and cause.
    /// \param message the exception message
    /// \param cause the exception which caused this to be generated
    AssertException(const std::string& message, const std::exception& cause)
        : std::runtime_error(message + " [caused by: " + cause.what() + "]") {}
};

} // namespace ghidra
