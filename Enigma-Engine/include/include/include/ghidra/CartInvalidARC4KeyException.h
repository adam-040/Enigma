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
/// \file CartInvalidARC4KeyException.h
/// \brief Exception for ARC4 key errors in CaRT format
/// Translated from: ghidra.file.formats.cart.CartInvalidARC4KeyException
#pragma once

#include "CartInvalidCartException.h"
#include <string>

namespace ghidra {

class CartInvalidARC4KeyException : public CartInvalidCartException {
public:
    explicit CartInvalidARC4KeyException(const std::string& message)
        : CartInvalidCartException(message) {}
};

} // namespace ghidra
