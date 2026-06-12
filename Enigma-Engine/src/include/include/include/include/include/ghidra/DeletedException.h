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
/// \file DeletedException.h
/// \brief Exception indicating that an object has been deleted
#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

/**
 * Exception indicating a data item has been deleted.
 * Translated from: ghidra.program.model.util.DeletedException
 * Java hierarchy: RuntimeException -> DeletedException
 */
class DeletedException : public std::runtime_error {
public:
    DeletedException()
        : std::runtime_error("Object has been deleted") {}

    explicit DeletedException(const std::string& msg)
        : std::runtime_error(msg) {}
};

} // namespace ghidra
