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
/// \file CancelledException.h
/// \brief Exception indicating that the user cancelled the current operation
#pragma once

#include "UsrException.h"

namespace ghidra {

/**
 * CancelledException indicates that the user cancelled
 * the current operation.
 * Translated from: ghidra.util.exception.CancelledException
 * Java hierarchy: Exception -> UsrException -> CancelledException
 */
class CancelledException : public UsrException {
public:
    /// Default constructor. Message indicates 'Operation cancelled'.
    CancelledException()
        : UsrException("Operation cancelled") {}

    /// Construct with custom message
    /// \param msg the exception message
    explicit CancelledException(const std::string& msg)
        : UsrException(msg) {}
};

} // namespace ghidra
