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
/// \file PNGFormatException.h
/// \brief Exception for PNG format errors
/// Translated from: ghidra.file.formats.ios.png.PNGFormatException
#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

class PNGFormatException : public std::exception {
private:
    std::string message_;

public:
    PNGFormatException() {}

    explicit PNGFormatException(const std::string& msg) : message_(msg) {}

    explicit PNGFormatException(const std::exception& cause) : message_(cause.what()) {}

    const char* what() const noexcept override { return message_.c_str(); }
};

} // namespace ghidra
