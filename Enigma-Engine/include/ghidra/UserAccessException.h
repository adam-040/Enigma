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
/// \file UserAccessException.h
/// \brief Exception thrown when a user does not have sufficient privileges for an operation
/// Translated from: ghidra.util.exception.UserAccessException
#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

class UserAccessException : public std::runtime_error {
public:
    UserAccessException() : std::runtime_error("User has insufficient privilege for operation.") {}

    explicit UserAccessException(const std::string& msg) : std::runtime_error(msg) {}
};

} // namespace ghidra
