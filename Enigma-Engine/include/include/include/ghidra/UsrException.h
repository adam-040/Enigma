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
/// \file UsrException.h
/// \brief Base class for all ghidra non-runtime exceptions
#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

/**
 * Base Class for all ghidra non-runtime exceptions.
 * Translated from: ghidra.util.exception.UsrException
 * Java hierarchy: Exception -> UsrException
 * C++ hierarchy: std::exception -> UsrException
 */
class UsrException : public std::exception {
private:
    std::string message_;

public:
    /// Construct a new UsrException with no message
    UsrException()
        : message_("") {}

    /// Construct a new UsrException with the given message
    /// \param msg the exception message
    explicit UsrException(const std::string& msg)
        : message_(msg) {}

    /// Construct a new UsrException with the given message and cause
    /// \param msg the exception message
    /// \param cause the exception cause
    UsrException(const std::string& msg, const std::exception& cause)
        : message_(msg + " [caused by: " + cause.what() + "]") {}

    const char* what() const noexcept override {
        return message_.c_str();
    }

    /// Get the exception message
    const std::string& getMessage() const { return message_; }
};

} // namespace ghidra
