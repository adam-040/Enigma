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
/// \file UnsatisfiedFieldsException.h
/// \brief Exception when fields lack suitable constructors
/// Translated from: generic.depends.err.UnsatisfiedFieldsException
#pragma once

#include <stdexcept>
#include <string>
#include <vector>

namespace ghidra {

class UnsatisfiedFieldsException : public std::exception {
private:
    std::string message_;
    std::vector<std::string> missing;

public:
    explicit UnsatisfiedFieldsException(const std::vector<std::string>& missing)
        : message_("There are fields without suitable constructors: " + joinMissing(missing)),
          missing(missing) {}

    const std::vector<std::string>& getMissing() const { return missing; }

    const char* what() const noexcept override { return message_.c_str(); }

private:
    static std::string joinMissing(const std::vector<std::string>& missing) {
        std::string result;
        for (size_t i = 0; i < missing.size(); ++i) {
            if (i > 0) result += ", ";
            result += missing[i];
        }
        return result;
    }
};

} // namespace ghidra
