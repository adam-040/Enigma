/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/MultiMemberAssign.h>
#include <ghidra/Encoder.h>
#include <ghidra/XmlPullParser.h>
#include <ghidra/ElementId.h>
#include <ghidra/AttributeId.h>
#include <ghidra/ParamListStandard.h>
#include <ghidra/PrimitiveExtractor.h>
#include <vector>

namespace ghidra {

MultiMemberAssign::MultiMemberAssign(StorageClass store, bool stack, bool mostSig, ParamListStandard* res)
    : AssignAction(res), resourceType(store), consumeFromStack(stack), consumeMostSig(mostSig) {
}

AssignAction* MultiMemberAssign::clone(ParamListStandard* newResource) {
    return new MultiMemberAssign(resourceType, consumeFromStack, consumeMostSig, newResource);
}

bool MultiMemberAssign::isEquivalent(const AssignAction& op) const {
    const auto* other = dynamic_cast<const MultiMemberAssign*>(&op);
    if (!other) return false;
    if (resourceType != other->resourceType) return false;
    if (consumeFromStack != other->consumeFromStack) return false;
    return consumeMostSig == other->consumeMostSig;
}

int MultiMemberAssign::assignAddress(DataType* dt, const PrototypePieces& proto, int pos,
                                     DataTypeManager* dtManager, int* status, ParameterPieces& res) {
    PrimitiveExtractor primitives(dt, false, 0, 16);
    if (!primitives.isValid() || primitives.size() == 0 || primitives.containsUnknown() ||
        !primitives.isAligned() || primitives.containsHoles()) {
        return FAIL;
    }
    std::vector<ParameterPieces> pieces;
    for (int i = 0; i < primitives.size(); ++i) {
        DataType* curType = primitives.get(i).dt;
        ParameterPieces param;
        if (resource->assignAddressFallback(resourceType, curType, !consumeFromStack, status, param) == FAIL) {
            return FAIL;
        }
        pieces.push_back(param);
    }
    res.type = dt;
    return SUCCESS;
}

void MultiMemberAssign::encode(Encoder& encoder) {
    encoder.openElement(ELEM_JOIN_PER_PRIMITIVE);
    if (resourceType != StorageClass::GENERAL) {
        encoder.writeString(ATTRIB_STORAGE, toString(resourceType));
    }
    encoder.closeElement(ELEM_JOIN_PER_PRIMITIVE);
}

void MultiMemberAssign::restoreXml(XmlPullParser& parser) {
    XmlElement elem = parser.nextElement();
    std::string storageStr = elem.getAttribute(ATTRIB_STORAGE.name);
    if (!storageStr.empty()) {
        resourceType = storageClassFromString(storageStr);
    }
    if (parser.hasNext()) parser.nextElement();
}

} // namespace ghidra
