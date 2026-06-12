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
/// \file NeedsBackfillException.h
/// \brief Exception indicating that the solution of an expression is not yet known and requires backfill
/// Translated from: ghidra.app.plugin.assembler.sleigh.expr.NeedsBackfillException
#pragma once

#include "SolverException.h"
#include <string>

namespace ghidra {

class NeedsBackfillException : public SolverException {
private:
    std::string symbol;

public:
    explicit NeedsBackfillException(const std::string& symbol)
        : SolverException("The symbol '" + symbol + "' is not yet available"), symbol(symbol) {}

    const std::string& getSymbol() const { return symbol; }
};

} // namespace ghidra
