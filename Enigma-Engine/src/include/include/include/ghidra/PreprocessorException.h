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
/// \file PreprocessorException.h
/// \brief Exception thrown during SLEIGH preprocessing
/// Translated from: ghidra.sleigh.grammar.PreprocessorException
#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

class PreprocessorException : public std::exception {
private:
    std::string message_;

public:
    PreprocessorException(const std::string& message, const std::string& filename,
                          int lineno, int overall, const std::string& line)
        : message_(message + " at " + filename + ":" + std::to_string(lineno) +
                   "(" + std::to_string(overall) + "): " + line) {}

    const char* what() const noexcept override { return message_.c_str(); }
};

} // namespace ghidra
