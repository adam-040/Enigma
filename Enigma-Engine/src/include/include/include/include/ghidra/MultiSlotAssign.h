/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file MultiSlotAssign.h
/// \brief Consume multiple registers to pass a data-type
/// Translated from: ghidra.program.model.lang.protorules.MultiSlotAssign
#pragma once

#include <ghidra/AssignAction.h>
#include <ghidra/StorageClass.h>
#include <vector>

namespace ghidra {

class ParamEntry;

class MultiSlotAssign : public AssignAction {
public:
    MultiSlotAssign(ParamListStandard* res);
    MultiSlotAssign(StorageClass store, bool stack, bool mostSig, bool align,
                    bool justRight, bool backfill, ParamListStandard* res);
    AssignAction* clone(ParamListStandard* newResource) override;
    bool isEquivalent(const AssignAction& op) const override;
    int assignAddress(DataType* dt, const PrototypePieces& proto, int pos,
                      DataTypeManager* dtManager, int* status, ParameterPieces& res) override;
    void encode(Encoder& encoder) override;
    void restoreXml(class XmlPullParser& parser) override;

private:
    StorageClass resourceType;
    bool isBigEndian;
    bool consumeFromStack;
    bool consumeMostSig;
    bool enforceAlignment;
    bool justifyRight;
    bool adjacentEntries;
    bool allowBackfill;
    std::vector<ParamEntry*> tiles;
    ParamEntry* stackEntry;

    void initializeEntries();
    bool checkFit(int iter, int sizeLeft, int align, int resourcesConsumed, int* tmpStatus);
};

} // namespace ghidra
