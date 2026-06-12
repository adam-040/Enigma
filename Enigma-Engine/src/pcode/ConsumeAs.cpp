/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/ConsumeAs.h>
#include <ghidra/Encoder.h>
#include <ghidra/XmlPullParser.h>
#include <ghidra/ElementId.h>
#include <ghidra/AttributeId.h>
#include <ghidra/ParamListStandard.h>

namespace ghidra {

ConsumeAs::ConsumeAs(StorageClass store, ParamListStandard* res)
    : AssignAction(res), resourceType(store) {
}

AssignAction* ConsumeAs::clone(ParamListStandard* newResource) {
    return new ConsumeAs(resourceType, newResource);
}

bool ConsumeAs::isEquivalent(const AssignAction& op) const {
    const auto* other = dynamic_cast<const ConsumeAs*>(&op);
    if (!other) return false;
    return resourceType == other->resourceType;
}

int ConsumeAs::assignAddress(DataType* dt, const PrototypePieces& proto, int pos,
                             DataTypeManager* dtManager, int* status, ParameterPieces& res) {
    return resource->assignAddressFallback(resourceType, dt, true, status, res);
}

void ConsumeAs::encode(Encoder& encoder) {
    encoder.openElement(ELEM_CONSUME);
    encoder.writeString(ATTRIB_STORAGE, toString(resourceType));
    encoder.closeElement(ELEM_CONSUME);
}

void ConsumeAs::restoreXml(XmlPullParser& parser) {
    XmlElement elem = parser.nextElement();
    std::string storageStr = elem.getAttribute(ATTRIB_STORAGE.name);
    if (!storageStr.empty()) {
        resourceType = storageClassFromString(storageStr);
    }
    if (parser.hasNext()) parser.nextElement();
}

} // namespace ghidra
