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
/// \file StatusListener.h
/// \brief General-purpose status listener interface
/// Translated from: ghidra.util.StatusListener
#pragma once

#include <string>

namespace ghidra {

/// \brief Message type for status messages.
enum class MessageType {
    INFO,
    WARNING,
    ERROR,
    STATUS
};

/// \brief General-purpose status listener for displaying/recording status messages.
class StatusListener {
public:
    virtual ~StatusListener() = default;

    /// \brief Set status text with INFO type.
    virtual void setStatusText(const std::string& text) = 0;

    /// \brief Set status text with a specified type.
    virtual void setStatusText(const std::string& text, MessageType type) = 0;

    /// \brief Set status text with specified type and alert flag.
    virtual void setStatusText(const std::string& text, MessageType type, bool alert) = 0;

    /// \brief Clear the current status text.
    virtual void clearStatusText() = 0;
};

} // namespace ghidra
