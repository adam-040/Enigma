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
/// \file DataTypeEncodeException.h
/// \brief Exception thrown when a value cannot be encoded for a data type
/// Translated from: ghidra.program.model.data.DataTypeEncodeException
#pragma once

#include "UsrException.h"
#include <string>

namespace ghidra {

class DataType;

class DataTypeEncodeException : public UsrException {
private:
    std::string value;
    const DataType* dt;

    static std::string computeMessage(const std::string& message, const std::string& value,
                                      const std::string& dtName, const std::exception* cause) {
        if (cause != nullptr) {
            std::string encodeError = "while encoding '" + value + "' for " + dtName;
            if (!message.empty()) {
                return std::string(cause->what()) + " (" + encodeError + ": " + message + ")";
            } else {
                return std::string(cause->what()) + " (" + encodeError + ")";
            }
        } else {
            std::string encodeError = "Cannot encode '" + value + "' for " + dtName;
            if (!message.empty()) {
                return encodeError + ": " + message;
            } else {
                return encodeError;
            }
        }
    }

public:
    DataTypeEncodeException(const std::string& message, const std::string& value,
                            const std::string& dtName)
        : UsrException(computeMessage(message, value, dtName, nullptr)),
          value(value), dt(nullptr) {}

    DataTypeEncodeException(const std::string& message, const std::string& value,
                            const std::string& dtName, const std::exception& cause)
        : UsrException(computeMessage(message, value, dtName, &cause)),
          value(value), dt(nullptr) {}

    const std::string& getValue() const { return value; }
};

} // namespace ghidra
