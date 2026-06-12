/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ConsumeAs.h
/// \brief Consume a parameter from a specific resource list
/// Translated from: ghidra.program.model.lang.protorules.ConsumeAs
#pragma once

#include <ghidra/AssignAction.h>
#include <ghidra/StorageClass.h>

namespace ghidra {

class ConsumeAs : public AssignAction {
public:
    ConsumeAs(StorageClass store, ParamListStandard* res);
    AssignAction* clone(ParamListStandard* newResource) override;
    bool isEquivalent(const AssignAction& op) const override;
    int assignAddress(DataType* dt, const PrototypePieces& proto, int pos,
                      DataTypeManager* dtManager, int* status, ParameterPieces& res) override;
    void encode(Encoder& encoder) override;
    void restoreXml(class XmlPullParser& parser) override;

private:
    StorageClass resourceType;
};

} // namespace ghidra
