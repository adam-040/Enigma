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
/// \file SleighFileLockException.h
/// \brief Exception thrown when a sleigh file lock cannot be obtained
/// Translated from: ghidra.app.plugin.processors.sleigh.SleighFileLockException
#pragma once

#include "SleighFileException.h"
#include <string>

namespace ghidra {

class SleighFileLockException : public SleighFileException {
public:
    explicit SleighFileLockException(const std::string& message) : SleighFileException(message) {}

    SleighFileLockException(const std::string& message, const std::exception& e)
        : SleighFileException(message + " (caused by: " + std::string(e.what()) + ")") {}
};

} // namespace ghidra
