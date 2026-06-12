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
/// \file VersionException.h
/// \brief Exception thrown when an object's version does not match its expected version
/// Translated from: ghidra.util.exception.VersionException
#pragma once

#include "UsrException.h"
#include <string>

namespace ghidra {

class VersionException : public UsrException {
public:
    static constexpr int UNKNOWN_VERSION = 0;
    static constexpr int OLDER_VERSION = 1;
    static constexpr int NEWER_VERSION = 2;

private:
    bool upgradeable = false;
    int versionIndicator = UNKNOWN_VERSION;
    std::string detailMessage;

    static std::string getDefaultMessage(bool upgradable);

public:
    VersionException();

    explicit VersionException(const std::string& msg) : UsrException(msg) {}

    explicit VersionException(bool upgradable);

    VersionException(int versionIndicator, bool upgradable);

    VersionException(const std::string& msg, int versionIndicator, bool upgradable)
        : UsrException(msg), upgradeable(upgradable), versionIndicator(versionIndicator) {}

    bool isUpgradable() const { return upgradeable; }

    int getVersionIndicator() const { return versionIndicator; }

    VersionException& combine(const VersionException& ve);

    void setDetailMessage(const std::string& message) { detailMessage = message; }

    const std::string& getDetailMessage() const { return detailMessage; }
};

} // namespace ghidra
