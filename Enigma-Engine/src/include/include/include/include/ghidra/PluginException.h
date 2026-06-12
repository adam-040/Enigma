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
/// \file PluginException.h
/// \brief Exception thrown if plugin was not found or cannot be added
/// Translated from: ghidra.framework.plugintool.util.PluginException
#pragma once

#include "UsrException.h"
#include <string>

namespace ghidra {

class PluginException : public UsrException {
public:
    PluginException(const std::string& className, const std::string& details)
        : UsrException("Can't add plugin: " + className + ".  " + details) {}

    explicit PluginException(const std::string& message) : UsrException(message) {}

    PluginException(const std::string& message, const std::exception& cause)
        : UsrException(message + " (caused by: " + std::string(cause.what()) + ")") {}

    PluginException getPluginException(const PluginException& e) const {
        return PluginException(e.what() + std::string("\n") + what());
    }
};

} // namespace ghidra
