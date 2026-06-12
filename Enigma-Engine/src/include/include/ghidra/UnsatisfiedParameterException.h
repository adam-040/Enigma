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
/// \file UnsatisfiedParameterException.h
/// \brief Exception when required parameters cannot be resolved
/// Translated from: generic.depends.err.UnsatisfiedParameterException
#pragma once

#include <stdexcept>
#include <string>
#include <vector>

namespace ghidra {

class UnsatisfiedParameterException : public std::exception {
private:
    std::string message_;
    std::vector<std::string> left;

public:
    explicit UnsatisfiedParameterException(const std::vector<std::string>& left)
        : message_("Could not resolve required parameter for next in: " + joinLeft(left) +
                   ". Note: it may be a circular dependency."),
          left(left) {}

    const std::vector<std::string>& getLeft() const { return left; }

    const char* what() const noexcept override { return message_.c_str(); }

private:
    static std::string joinLeft(const std::vector<std::string>& left) {
        std::string result;
        for (size_t i = 0; i < left.size(); ++i) {
            if (i > 0) result += ", ";
            result += left[i];
        }
        return result;
    }
};

} // namespace ghidra
