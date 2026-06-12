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
/// \file ArchiveType.h
/// \brief Specifies the type of data type archive
/// Translated from: ghidra.program.model.data.ArchiveType
#pragma once

namespace ghidra {

enum class ArchiveType {
    BUILT_IN,
    FILE,
    PROJECT,
    PROGRAM,
    TEMPORARY
};

namespace ArchiveTypeUtil {

    inline bool isBuiltIn(ArchiveType type) {
        return type == ArchiveType::BUILT_IN;
    }

    inline bool isValidSourceArchive(ArchiveType type) {
        return type == ArchiveType::FILE || type == ArchiveType::PROJECT;
    }

} // namespace ArchiveTypeUtil

} // namespace ghidra
