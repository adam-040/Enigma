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
/// \file OptionException.h
/// \brief Exception for problems accessing an Option or conveying informational messages
/// Translated from: ghidra.app.util.OptionException
#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

class OptionException : public std::exception {
private:
    std::string message_;
    bool isInfo = false;

public:
    explicit OptionException(const std::string& msg) : message_(msg) {}

    OptionException(const std::string& msg, bool isInfo) : message_(msg), isInfo(isInfo) {}

    const char* what() const noexcept override { return message_.c_str(); }

    bool isInfoMessage() const { return isInfo; }
};

} // namespace ghidra
