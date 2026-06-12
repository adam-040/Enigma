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
/// \file BadSchemaException.h
/// \brief Exception indicating a path or object does not provide a required interface
/// Translated from: ghidra.trace.model.target.schema.BadSchemaException
#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

class BadSchemaException : public std::runtime_error {
public:
    explicit BadSchemaException(const std::string& message) : std::runtime_error(message) {}
};

} // namespace ghidra
