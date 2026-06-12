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
/// \file DomainObjectException.h
/// \brief General RuntimeException for catastrophic errors affecting domain object integrity
/// Translated from: ghidra.framework.model.DomainObjectException
#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

class DomainObjectException : public std::runtime_error {
private:
    std::string causeMessage;

public:
    explicit DomainObjectException(const std::exception& t)
        : std::runtime_error(std::string("DomainObjectException caused by: ") + t.what()),
          causeMessage(t.what()) {}

    const std::string& getCauseMessage() const { return causeMessage; }
};

} // namespace ghidra
