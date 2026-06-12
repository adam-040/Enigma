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
/// \file ByteBlockAccessException.h
/// \brief Exception indicating that byte block access is not permitted
/// Translated from: ghidra.app.plugin.core.format.ByteBlockAccessException
#pragma once

#include "UsrException.h"
#include <string>

namespace ghidra {

class ByteBlockAccessException : public UsrException {
public:
    ByteBlockAccessException() : UsrException() {}

    explicit ByteBlockAccessException(const std::string& message) : UsrException(message) {}

    ByteBlockAccessException(const std::string& message, const std::exception& cause)
        : UsrException(message + " (caused by: " + std::string(cause.what()) + ")") {}
};

} // namespace ghidra
