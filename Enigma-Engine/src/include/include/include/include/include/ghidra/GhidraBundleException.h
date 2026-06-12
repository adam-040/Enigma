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
/// \file GhidraBundleException.h
/// \brief Exception storing context associated with bundle operations
/// Translated from: ghidra.app.plugin.core.osgi.GhidraBundleException
#pragma once

#include "OSGiException.h"
#include <string>

namespace ghidra {

class GhidraBundleException : public OSGiException {
private:
    std::string bundleLocation;

public:
    GhidraBundleException(const std::string& bundleLocation, const std::string& msg, const std::exception& cause)
        : OSGiException(msg + ": " + std::string(cause.what()), cause),
          bundleLocation(bundleLocation) {}

    GhidraBundleException(const std::string& bundleLocation, const std::string& msg)
        : OSGiException(msg), bundleLocation(bundleLocation) {}

    const std::string& getBundleLocation() const { return bundleLocation; }
};

} // namespace ghidra
