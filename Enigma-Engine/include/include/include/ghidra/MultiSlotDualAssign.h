/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file MultiSlotDualAssign.h
/// \brief Consume multiple registers from different storage classes
/// Translated from: ghidra.program.model.lang.protorules.MultiSlotDualAssign
#pragma once

#include <ghidra/AssignAction.h>
#include <ghidra/StorageClass.h>
#include <vector>

namespace ghidra {

class ParamEntry;
class PrimitiveExtractor;

class MultiSlotDualAssign : public AssignAction {
public:
    MultiSlotDualAssign(ParamListStandard* res);
    MultiSlotDualAssign(StorageClass baseStore, StorageClass altStore, bool stack,
                        bool mostSig, bool justRight, bool fillAlt, ParamListStandard* res);
    AssignAction* clone(ParamListStandard* newResource) override;
    bool isEquivalent(const AssignAction& op) const override;
    int assignAddress(DataType* dt, const PrototypePieces& proto, int pos,
                      DataTypeManager* dtManager, int* status, ParameterPieces& res) override;
    void encode(Encoder& encoder) override;
    void restoreXml(class XmlPullParser& parser) override;

private:
    StorageClass baseType;
    StorageClass altType;
    bool isBigEndian;
    bool consumeFromStack;
    bool consumeMostSig;
    bool justifyRight;
    bool fillAlternate;
    int tileSize;
    std::vector<ParamEntry*> baseTiles;
    std::vector<ParamEntry*> altTiles;
    ParamEntry* stackEntry;

    void initializeEntries();
    int getFirstUnused(int iter, std::vector<ParamEntry*>& tiles, int* status);
    int getTileClass(class PrimitiveExtractor& primitives, int off, int* index);
};

} // namespace ghidra
