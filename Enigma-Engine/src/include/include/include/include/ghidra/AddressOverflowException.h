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
/// \file AddressOverflowException.h
/// \brief Exception thrown when a displacement would result in an illegal address value
/// Translated from: ghidra.program.model.address.AddressOverflowException
#pragma once

#include "UsrException.h"
#include <string>

namespace ghidra {

class AddressOverflowException : public UsrException {
public:
    AddressOverflowException() : UsrException("Displacement would result in an illegal address value.") {}

    explicit AddressOverflowException(const std::string& message) : UsrException(message) {}
};

} // namespace ghidra
