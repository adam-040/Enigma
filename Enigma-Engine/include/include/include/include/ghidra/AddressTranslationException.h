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
/// \file AddressTranslationException.h
/// \brief Exception thrown when address translation between programs fails
/// Translated from: ghidra.program.util.AddressTranslationException
#pragma once

#include "Address.h"
#include <stdexcept>
#include <string>

namespace ghidra {

class AddressTranslator;

class AddressTranslationException : public std::runtime_error {
private:
    Address address;
    const AddressTranslator* translator = nullptr;

public:
    AddressTranslationException() : std::runtime_error("") {}

    explicit AddressTranslationException(const std::string& msg) : std::runtime_error(msg) {}

    AddressTranslationException(const Address& address, const AddressTranslator& translator)
        : std::runtime_error("Cannot translate address \"" + address.toString() + "\"."),
          address(address), translator(&translator) {}

    const Address& getAddress() const { return address; }
    const AddressTranslator* getTranslator() const { return translator; }
};

} // namespace ghidra
