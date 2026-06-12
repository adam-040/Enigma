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
/// \file NotOwnerException.h
/// \brief Exception thrown if user is not the owner of a file or data object
/// Translated from: ghidra.util.NotOwnerException
#pragma once

#include "UsrException.h"
#include <string>

namespace ghidra {

class NotOwnerException : public UsrException {
public:
    NotOwnerException() : UsrException("User is not the owner") {}

    explicit NotOwnerException(const std::string& msg) : UsrException(msg) {}
};

} // namespace ghidra
