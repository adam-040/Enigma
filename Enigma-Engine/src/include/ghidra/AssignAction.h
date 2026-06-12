/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AssignAction.h
/// \brief Abstract base for parameter storage assignment actions
/// Translated from: ghidra.program.model.lang.protorules.AssignAction
#pragma once

#include <ghidra/Encoder.h>
#include <ghidra/PrototypePieces.h>
#include <ghidra/ParameterPieces.h>
#include <ghidra/DataType.h>
#include <vector>

namespace ghidra {

class ParamListStandard;
class DataTypeManager;

class AssignAction {
public:
    static constexpr int SUCCESS = 0;
    static constexpr int FAIL = 1;
    static constexpr int NO_ASSIGNMENT = 2;
    static constexpr int HIDDENRET_PTRPARAM = 3;
    static constexpr int HIDDENRET_SPECIALREG = 4;
    static constexpr int HIDDENRET_SPECIALREG_VOID = 5;

    ParamListStandard* resource;

    explicit AssignAction(ParamListStandard* res) : resource(res) {}
    virtual ~AssignAction() = default;

    virtual AssignAction* clone(ParamListStandard* newResource) = 0;
    virtual bool isEquivalent(const AssignAction& op) const = 0;
    virtual int assignAddress(DataType* dt, const PrototypePieces& proto, int pos,
                              DataTypeManager* dtManager, int* status, ParameterPieces& res) = 0;
    virtual void encode(Encoder& encoder) = 0;
    virtual void restoreXml(class XmlPullParser& parser) = 0;

    static AssignAction* restoreActionXml(class XmlPullParser& parser, ParamListStandard* res);
    static AssignAction* restoreSideeffectXml(class XmlPullParser& parser, ParamListStandard* res);
    static AssignAction* restorePreconditionXml(class XmlPullParser& parser, ParamListStandard* res);

    static void justifyPieces(std::vector<class Varnode*>& pieces, int offset,
                              bool isBigEndian, bool consumeMostSig, bool justifyRight);
};

} // namespace ghidra
