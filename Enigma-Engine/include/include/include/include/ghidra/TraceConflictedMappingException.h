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
/// \file TraceConflictedMappingException.h
/// \brief Exception when trace static mappings conflict
/// Translated from: ghidra.trace.model.modules.TraceConflictedMappingException
#pragma once

#include <stdexcept>
#include <string>
#include <vector>

namespace ghidra {

class TraceStaticMapping;

class TraceConflictedMappingException : public std::runtime_error {
private:
    std::vector<const TraceStaticMapping*> conflicts;

public:
    TraceConflictedMappingException(const std::string& message,
                                    const std::vector<const TraceStaticMapping*>& conflicts)
        : std::runtime_error(message + ": " + std::to_string(conflicts.size()) + " conflicts"),
          conflicts(conflicts) {}

    const std::vector<const TraceStaticMapping*>& getConflicts() const { return conflicts; }
};

} // namespace ghidra
