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
/// \file LockException.h
/// \brief Exception indicating a failure to obtain a required lock
/// Translated from: ghidra.framework.store.LockException
#pragma once

#include "UsrException.h"
#include <string>

namespace ghidra {

class LockException : public UsrException {
public:
    explicit LockException(const std::string& msg) : UsrException(msg) {}
};

} // namespace ghidra
