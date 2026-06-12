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
/// \file FunctionComparisonException.h
/// \brief Exception thrown when comparing functions or applying information between them fails
/// Translated from: ghidra.features.bsim.gui.search.results.FunctionComparisonException
#pragma once

#include "UsrException.h"
#include <string>

namespace ghidra {

class FunctionComparisonException : public UsrException {
public:
    explicit FunctionComparisonException(const std::string& msg) : UsrException(msg) {}

    FunctionComparisonException(const std::string& msg, const std::exception& cause)
        : UsrException(msg + " (caused by: " + std::string(cause.what()) + ")") {}
};

} // namespace ghidra
