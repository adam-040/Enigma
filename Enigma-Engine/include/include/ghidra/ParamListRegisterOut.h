/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ParamListRegisterOut.h
/// \brief Register-based output parameter list (no hidden return)
/// Translated from: ghidra.program.model.lang.ParamListRegisterOut
#pragma once

#include <ghidra/ParamListStandardOut.h>

namespace ghidra {

class ParamListRegisterOut : public ParamListStandardOut {
public:
    ParamList* clone() const override { return new ParamListRegisterOut(*this); }
    void assignMap(const PrototypePieces& proto, DataTypeManager* dtManager,
                   std::vector<ParameterPieces>& res, bool addAutoParams) override;
};

} // namespace ghidra
