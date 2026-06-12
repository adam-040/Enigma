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
/// \file SledException.h
/// \brief Exception generated from parsing SLED/SSL configuration files
/// Translated from: ghidra.app.plugin.processors.generic.SledException
#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

class SledException : public std::runtime_error {
public:
    SledException() : std::runtime_error("") {}

    explicit SledException(const std::string& message) : std::runtime_error(message) {}

    SledException(const std::string& message, const std::exception& cause)
        : std::runtime_error(message + " (caused by: " + std::string(cause.what()) + ")") {}
};

} // namespace ghidra
