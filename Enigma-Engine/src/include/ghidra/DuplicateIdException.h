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
/// \file DuplicateIdException.h
/// \brief Exception when attempting to open a datatype archive with a duplicate ID
/// Translated from: ghidra.app.plugin.core.datamgr.archive.DuplicateIdException
#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

class DuplicateIdException : public std::exception {
private:
    std::string message_;
    std::string newArchiveName;
    std::string existingArchiveName;

public:
    DuplicateIdException(const std::string& newArchiveName, const std::string& existingArchiveName)
        : message_("Attempted to open a datatype archive with the same ID as datatype archive that is\n "
                   "already open. " + newArchiveName + " has same id as " + existingArchiveName +
                   "\nOne is probably a copy of the other.  Ghidra does not support using \n"
                   "archive copies within the same project!"),
          newArchiveName(newArchiveName),
          existingArchiveName(existingArchiveName) {}

    const std::string& getNewArchiveName() const { return newArchiveName; }
    const std::string& getExistingArchiveName() const { return existingArchiveName; }

    const char* what() const noexcept override { return message_.c_str(); }
};

} // namespace ghidra
