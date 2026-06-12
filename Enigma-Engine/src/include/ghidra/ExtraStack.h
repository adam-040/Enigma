/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ExtraStack.h
/// \brief Consume stack resources as a side-effect
/// Translated from: ghidra.program.model.lang.protorules.ExtraStack
#pragma once

#include <ghidra/AssignAction.h>
#include <ghidra/StorageClass.h>

namespace ghidra {

class ParamEntry;

class ExtraStack : public AssignAction {
public:
    ExtraStack(ParamListStandard* res, int val);
    ExtraStack(StorageClass storage, int offset, ParamListStandard* res);
    AssignAction* clone(ParamListStandard* newResource) override;
    bool isEquivalent(const AssignAction& op) const override;
    int assignAddress(DataType* dt, const PrototypePieces& proto, int pos,
                      DataTypeManager* dtManager, int* status, ParameterPieces& res) override;
    void encode(Encoder& encoder) override;
    void restoreXml(class XmlPullParser& parser) override;

private:
    int afterBytes;
    StorageClass afterStorage;
    ParamEntry* stackEntry;
    void initializeEntry();
};

} // namespace ghidra
