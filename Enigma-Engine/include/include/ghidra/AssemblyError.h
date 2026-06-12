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
/// \file AssemblyError.h
/// \brief Exception for programmer errors regarding an assembler
/// Translated from: ghidra.app.plugin.assembler.AssemblyError
#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

class AssemblyError : public std::runtime_error {
public:
    explicit AssemblyError(const std::string& message) : std::runtime_error(message) {}
};

} // namespace ghidra
