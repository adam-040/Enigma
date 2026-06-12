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
/// \file UnknownArtStorageModeException.h
/// \brief Exception for unrecognized ART storage mode
/// Translated from: ghidra.file.formats.android.art.UnknownArtStorageModeException
#pragma once

#include <stdexcept>
#include <string>
#include <sstream>
#include <iomanip>

namespace ghidra {

class UnknownArtStorageModeException : public std::runtime_error {
public:
    explicit UnknownArtStorageModeException(int storageMode)
        : std::runtime_error(formatMessage(storageMode)) {}

private:
    static std::string formatMessage(int storageMode) {
        std::stringstream ss;
        ss << "Unrecognized storage mode: 0x" << std::hex << storageMode;
        return ss.str();
    }
};

} // namespace ghidra
