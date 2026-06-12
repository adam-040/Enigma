/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ConvertToPointer.h
/// \brief Action converting a parameter's data-type to a pointer and assigning pointer storage
/// Translated from: ghidra.program.model.lang.protorules.ConvertToPointer
#pragma once

#include <ghidra/AssignAction.h>

namespace ghidra {

class AddressSpace;

class ConvertToPointer : public AssignAction {
private:
    AddressSpace* space;

public:
    explicit ConvertToPointer(ParamListStandard* res, AddressSpace* spc = nullptr);

    AssignAction* clone(ParamListStandard* newResource) override;
    bool isEquivalent(const AssignAction& op) const override;
    int assignAddress(DataType* dt, const PrototypePieces& proto, int pos,
                      DataTypeManager* dtManager, int* status, ParameterPieces& res) override;
    void encode(Encoder& encoder) override;
    void restoreXml(class XmlPullParser& parser) override;
};

} // namespace ghidra
