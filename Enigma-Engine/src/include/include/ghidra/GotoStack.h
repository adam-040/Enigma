/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file GotoStack.h
/// \brief Action assigning a parameter Address from the next available stack location
/// Translated from: ghidra.program.model.lang.protorules.GotoStack
#pragma once

#include <ghidra/AssignAction.h>

namespace ghidra {

class ParamEntry;

class GotoStack : public AssignAction {
public:
    GotoStack(ParamListStandard* res, int val);
    explicit GotoStack(ParamListStandard* res);
    AssignAction* clone(ParamListStandard* newResource) override;
    bool isEquivalent(const AssignAction& op) const override;
    int assignAddress(DataType* dt, const PrototypePieces& proto, int pos,
                      DataTypeManager* dtManager, int* status, ParameterPieces& res) override;
    void encode(Encoder& encoder) override;
    void restoreXml(class XmlPullParser& parser) override;

private:
    ParamEntry* stackEntry;
    void initializeEntry();
};

} // namespace ghidra
