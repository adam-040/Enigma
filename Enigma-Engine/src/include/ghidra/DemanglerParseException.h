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
/// \file DemanglerParseException.h
/// \brief Exception signaling a problem parsing a demangled string
/// Translated from: ghidra.app.util.demangler.gnu.DemanglerParseException
#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

class DemanglerParseException : public std::runtime_error {
public:
    explicit DemanglerParseException(const std::string& message) : std::runtime_error(message) {}
};

} // namespace ghidra
