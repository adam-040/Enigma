/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PrototypeModelMerged.cpp
#include "ghidra/PrototypeModelMerged.h"
#include "ghidra/Address.h"
#include "ghidra/Parameter.h"
#include "ghidra/VariableStorage.h"
#include "ghidra/PcodeInjectLibrary.h"

namespace ghidra {

PrototypeModelMerged::PrototypeModelMerged() : PrototypeModel() {}

void PrototypeModelMerged::encode(Encoder& encoder, PcodeInjectLibrary* injectLibrary) {
    (void)injectLibrary;
    encoder.openElement(ELEM_RESOLVEPROTOTYPE);
    encoder.writeString(ATTRIB_NAME, getName());
    for (PrototypeModel* model : modellist) {
        encoder.openElement(ELEM_MODEL);
        encoder.writeString(ATTRIB_NAME, model->getName());
        encoder.closeElement(ELEM_MODEL);
    }
    encoder.closeElement(ELEM_RESOLVEPROTOTYPE);
}

void PrototypeModelMerged::restoreXml(XmlPullParser* parser, const std::vector<PrototypeModel*>& modelList) {
    (void)parser; (void)modelList;
    modellist.clear();
}

PrototypeModel* PrototypeModelMerged::selectModel(const std::vector<Parameter*>& params) {
    int bestScore = 500;
    int bestIndex = -1;
    for (size_t i = 0; i < modellist.size(); ++i) {
        int score = 0;
        int mismatch = 0;
        for (Parameter* p : params) {
            if (p == nullptr) continue;
            VariableStorage storage = p->getVariableStorage();
            if (storage.isUnassignedStorage() || storage.isBadStorage()) continue;
            ParamList::WithSlotRec rec;
            bool isparam = modellist[i]->possibleInputParamWithSlot(
                storage.getMinAddress(), p->getLength(), rec);
            if (!isparam) {
                mismatch += 1;
            } else {
                int gap = rec.slot;
                if (gap > 0) score += 10;
                score += mismatch * 20;
            }
        }
        score += mismatch * 20;
        if (score < bestScore) {
            bestScore = score;
            bestIndex = (int)i;
            if (bestScore == 0) break;
        }
    }
    if (bestIndex >= 0) return modellist[bestIndex];
    return nullptr;
}

bool PrototypeModelMerged::isEquivalent(const PrototypeModel& obj) const {
    if (typeid(*this) != typeid(obj)) return false;
    auto* op2 = dynamic_cast<const PrototypeModelMerged*>(&obj);
    if (op2 == nullptr) return false;
    if (modellist.size() != op2->modellist.size()) return false;
    for (size_t i = 0; i < modellist.size(); ++i) {
        if (modellist[i]->getName() != op2->modellist[i]->getName()) return false;
    }
    return true;
}

} // namespace ghidra
