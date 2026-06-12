/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ParamListStandardOut.h
/// \brief Output (return value) parameter list with hidden return pointer support
/// Translated from: ghidra.program.model.lang.ParamListStandardOut
#pragma once

#include <ghidra/ParamListStandard.h>

namespace ghidra {

class ParamListStandardOut : public ParamListStandard {
public:
    ParamList* clone() const override { return new ParamListStandardOut(*this); }
    void assignMap(const PrototypePieces& proto, DataTypeManager* dtManager,
                   std::vector<ParameterPieces>& res, bool addAutoParams) override;
};

} // namespace ghidra
