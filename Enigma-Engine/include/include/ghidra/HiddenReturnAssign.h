/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file HiddenReturnAssign.h
/// \brief Allocate the return value as an input parameter
/// Translated from: ghidra.program.model.lang.protorules.HiddenReturnAssign
#pragma once

#include <ghidra/AssignAction.h>

namespace ghidra {

class HiddenReturnAssign : public AssignAction {
public:
    static constexpr const char* STRATEGY_SPECIAL = "special";
    static constexpr const char* STRATEGY_NORMAL = "normalparam";

    HiddenReturnAssign(ParamListStandard* res, int code);
    AssignAction* clone(ParamListStandard* newResource) override;
    bool isEquivalent(const AssignAction& op) const override;
    int assignAddress(DataType* dt, const PrototypePieces& proto, int pos,
                      DataTypeManager* dtManager, int* status, ParameterPieces& res) override;
    void encode(Encoder& encoder) override;
    void restoreXml(class XmlPullParser& parser) override;

private:
    int retCode;
};

} // namespace ghidra
