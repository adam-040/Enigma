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
/// \file IOCancelledException.h
/// \brief An IO operation was cancelled by the user
#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

/**
 * An IO operation was cancelled by the user.
 * Translated from: ghidra.util.exception.IOCancelledException
 * Java hierarchy: IOException -> IOCancelledException
 * C++ hierarchy: std::runtime_error (as IOException equivalent) -> IOCancelledException
 */
class IOException : public std::runtime_error {
public:
    IOException()
        : std::runtime_error("IO error") {}
    explicit IOException(const std::string& msg)
        : std::runtime_error(msg) {}
};

class IOCancelledException : public IOException {
public:
    /// Default constructor
    IOCancelledException()
        : IOException("IO cancelled by user") {}

    /// Constructor with message
    /// \param msg detailed message
    explicit IOCancelledException(const std::string& msg)
        : IOException(msg) {}
};

} // namespace ghidra
