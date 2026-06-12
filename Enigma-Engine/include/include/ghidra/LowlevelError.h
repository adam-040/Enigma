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
/// \file LowlevelError.h
/// \brief Low-level runtime errors in the pcode framework
#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

/**
 * Low-level runtime error in pcode processing.
 * Translated from: ghidra.pcode.error.LowlevelError
 * Java hierarchy: RuntimeException -> LowlevelError
 */
class LowlevelError : public std::runtime_error {
public:
    explicit LowlevelError(const std::string& message)
        : std::runtime_error(message) {}

    LowlevelError(const std::string& message, const std::exception& cause)
        : std::runtime_error(message + " [caused by: " + cause.what() + "]") {}
};

/**
 * Error for unimplemented instructions.
 * Translated from: ghidra.pcodeCPort.translate.UnimplError
 * Java hierarchy: RuntimeException -> LowlevelError -> UnimplError
 */
class UnimplError : public LowlevelError {
public:
    int instruction_length;

    UnimplError(const std::string& message, int instruction_length)
        : LowlevelError(message), instruction_length(instruction_length) {}
};

/**
 * Error for bad data encountered during processing.
 * Translated from: ghidra.pcodeCPort.translate.BadDataError
 * Java hierarchy: RuntimeException -> LowlevelError -> BadDataError
 */
class BadDataError : public LowlevelError {
public:
    explicit BadDataError(const std::string& message)
        : LowlevelError(message) {}
};

} // namespace ghidra
