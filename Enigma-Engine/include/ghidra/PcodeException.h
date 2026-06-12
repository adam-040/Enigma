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
/// \file PcodeException.h
/// \brief Exceptions related to Pcode processing
#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

/**
 * Exception generated from problems with Pcode.
 * Translated from: ghidra.program.model.pcode.PcodeException
 * Java hierarchy: Exception -> PcodeException
 */
class PcodeException : public std::exception {
private:
    std::string message_;
public:
    explicit PcodeException(const std::string& msg)
        : message_("Pcode: " + msg) {}

    PcodeException(const std::string& msg, const std::exception& cause)
        : message_("Pcode: " + msg + " [caused by: " + cause.what() + "]") {}

    const char* what() const noexcept override {
        return message_.c_str();
    }
};

/**
 * Exception thrown for errors decoding decompiler objects from stream.
 * Translated from: ghidra.program.model.pcode.DecoderException
 * Java hierarchy: Exception -> PcodeException -> DecoderException
 */
class DecoderException : public PcodeException {
public:
    explicit DecoderException(const std::string& msg)
        : PcodeException("Decoding error: " + msg) {}

    DecoderException(const std::string& msg, const std::exception& cause)
        : PcodeException("Decoding error: " + msg, cause) {}
};

} // namespace ghidra
