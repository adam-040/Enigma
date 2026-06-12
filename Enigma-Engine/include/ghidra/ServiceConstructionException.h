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
/// \file ServiceConstructionException.h
/// \brief Exception for service construction errors
/// Translated from: generic.depends.err.ServiceConstructionException
#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

class ServiceConstructionException : public std::exception {
private:
    std::string message_;

public:
    ServiceConstructionException(const std::string& message, const std::exception& cause)
        : message_(message + " (caused by: " + std::string(cause.what()) + ")") {}

    const char* what() const noexcept override { return message_.c_str(); }
};

} // namespace ghidra
