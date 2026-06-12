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
/// \file DomainObjectLockedException.h
/// \brief Exception thrown when a method fails due to a locked domain object
/// Translated from: ghidra.framework.model.DomainObjectLockedException
#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

class DomainObjectLockedException : public std::runtime_error {
public:
    explicit DomainObjectLockedException(const std::string& reason)
        : std::runtime_error("Domain object is locked by " + reason) {}
};

} // namespace ghidra
