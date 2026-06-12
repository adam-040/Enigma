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
/// \file AssemblySemanticException.h
/// \brief Exception thrown when all resolutions of an assembly instruction result in semantic errors
/// Translated from: ghidra.app.plugin.assembler.AssemblySemanticException
#pragma once

#include "AssemblyException.h"
#include <string>
#include <vector>

namespace ghidra {

class AssemblySemanticException : public AssemblyException {
protected:
    std::vector<std::string> errors;

public:
    explicit AssemblySemanticException(const std::string& message) : AssemblyException(message) {}

    explicit AssemblySemanticException(const std::vector<std::string>& errors)
        : AssemblyException(joinErrors(errors)), errors(errors) {}

    const std::vector<std::string>& getErrors() const { return errors; }

private:
    static std::string joinErrors(const std::vector<std::string>& errors) {
        std::string result;
        for (size_t i = 0; i < errors.size(); ++i) {
            if (i > 0) result += "\n";
            result += errors[i];
        }
        return result;
    }
};

} // namespace ghidra
