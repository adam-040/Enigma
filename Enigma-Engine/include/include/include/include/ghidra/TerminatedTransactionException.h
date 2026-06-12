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
/// \file TerminatedTransactionException.h
/// \brief Exception thrown when a database modification is attempted after transaction termination
/// Translated from: db.TerminatedTransactionException
#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

class TerminatedTransactionException : public std::runtime_error {
public:
    TerminatedTransactionException() : std::runtime_error("Transaction has been terminated") {}

    explicit TerminatedTransactionException(const std::string& msg) : std::runtime_error(msg) {}
};

} // namespace ghidra
