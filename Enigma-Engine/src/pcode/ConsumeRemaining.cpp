/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/ConsumeRemaining.h>
#include <ghidra/Encoder.h>
#include <ghidra/XmlPullParser.h>
#include <ghidra/ElementId.h>
#include <ghidra/AttributeId.h>
#include <ghidra/ParamListStandard.h>
#include <ghidra/ParamEntry.h>
#include <stdexcept>

namespace ghidra {

void ConsumeRemaining::initializeEntries() {
    if (!resource) return;
    std::vector<ParamEntry> tmp = resource->extractTiles(resourceType);
    tiles.clear();
    for (auto& entry : tmp) {
        tiles.push_back(&entry);
    }
    if (tiles.empty()) {
        throw std::runtime_error("Could not find matching resources for action: consume_remaining");
    }
}

ConsumeRemaining::ConsumeRemaining(ParamListStandard* res)
    : AssignAction(res), resourceType(StorageClass::GENERAL) {
}

ConsumeRemaining::ConsumeRemaining(StorageClass store, ParamListStandard* res)
    : AssignAction(res), resourceType(store) {
    initializeEntries();
}

AssignAction* ConsumeRemaining::clone(ParamListStandard* newResource) {
    return new ConsumeRemaining(resourceType, newResource);
}

bool ConsumeRemaining::isEquivalent(const AssignAction& op) const {
    const auto* other = dynamic_cast<const ConsumeRemaining*>(&op);
    if (!other) return false;
    if (resourceType != other->resourceType) return false;
    if (tiles.size() != other->tiles.size()) return false;
    for (size_t i = 0; i < tiles.size(); ++i) {
        if (!tiles[i]->isEquivalent(*other->tiles[i])) return false;
    }
    return true;
}

int ConsumeRemaining::assignAddress(DataType* dt, const PrototypePieces& proto, int pos,
                                    DataTypeManager* dtManager, int* status, ParameterPieces& res) {
    size_t iter = 0;
    while (iter != tiles.size()) {
        ParamEntry* entry = tiles[iter];
        ++iter;
        if (status[entry->getGroup()] != 0) continue;
        status[entry->getGroup()] = -1;
    }
    return SUCCESS;
}

void ConsumeRemaining::encode(Encoder& encoder) {
    encoder.openElement(ELEM_CONSUME_REMAINING);
    encoder.writeString(ATTRIB_STORAGE, toString(resourceType));
    encoder.closeElement(ELEM_CONSUME_REMAINING);
}

void ConsumeRemaining::restoreXml(XmlPullParser& parser) {
    XmlElement elem = parser.nextElement();
    std::string storageStr = elem.getAttribute(ATTRIB_STORAGE.name);
    if (!storageStr.empty()) {
        resourceType = storageClassFromString(storageStr);
    }
    if (parser.hasNext()) parser.nextElement();
    try {
        initializeEntries();
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("XmlParseException: ") + e.what());
    }
}

} // namespace ghidra
