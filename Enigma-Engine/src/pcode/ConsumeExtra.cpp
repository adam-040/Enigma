/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/ConsumeExtra.h>
#include <ghidra/Encoder.h>
#include <ghidra/XmlPullParser.h>
#include <ghidra/ElementId.h>
#include <ghidra/AttributeId.h>
#include <ghidra/ParamListStandard.h>
#include <ghidra/ParamEntry.h>
#include <stdexcept>

namespace ghidra {

void ConsumeExtra::initializeEntries() {
    if (!resource) return;
    std::vector<ParamEntry> tmp = resource->extractTiles(resourceType);
    tiles.clear();
    for (auto& entry : tmp) {
        tiles.push_back(&entry);
    }
    if (tiles.empty()) {
        throw std::runtime_error("Could not find matching resources for action: consume_extra");
    }
}

ConsumeExtra::ConsumeExtra(ParamListStandard* res)
    : AssignAction(res), resourceType(StorageClass::GENERAL), matchSize(true) {
}

ConsumeExtra::ConsumeExtra(StorageClass store, bool match, ParamListStandard* res)
    : AssignAction(res), resourceType(store), matchSize(match) {
    initializeEntries();
}

AssignAction* ConsumeExtra::clone(ParamListStandard* newResource) {
    return new ConsumeExtra(resourceType, matchSize, newResource);
}

bool ConsumeExtra::isEquivalent(const AssignAction& op) const {
    const auto* other = dynamic_cast<const ConsumeExtra*>(&op);
    if (!other) return false;
    if (matchSize != other->matchSize || resourceType != other->resourceType) return false;
    if (tiles.size() != other->tiles.size()) return false;
    for (size_t i = 0; i < tiles.size(); ++i) {
        if (!tiles[i]->isEquivalent(*other->tiles[i])) return false;
    }
    return true;
}

int ConsumeExtra::assignAddress(DataType* dt, const PrototypePieces& proto, int pos,
                                DataTypeManager* dtManager, int* status, ParameterPieces& res) {
    size_t iter = 0;
    int sizeLeft = dt->getLength();
    while (sizeLeft > 0 && iter != tiles.size()) {
        ParamEntry* entry = tiles[iter];
        ++iter;
        if (status[entry->getGroup()] != 0) continue;
        status[entry->getGroup()] = -1;
        sizeLeft -= entry->getSize();
        if (!matchSize) break;
    }
    return SUCCESS;
}

void ConsumeExtra::encode(Encoder& encoder) {
    encoder.openElement(ELEM_CONSUME_EXTRA);
    encoder.writeString(ATTRIB_STORAGE, toString(resourceType));
    encoder.writeBool(ATTRIB_MATCHSIZE, matchSize);
    encoder.closeElement(ELEM_CONSUME_EXTRA);
}

void ConsumeExtra::restoreXml(XmlPullParser& parser) {
    XmlElement elem = parser.nextElement();
    std::string storageStr = elem.getAttribute(ATTRIB_STORAGE.name);
    if (!storageStr.empty()) {
        resourceType = storageClassFromString(storageStr);
    }
    std::string matchStr = elem.getAttribute(ATTRIB_MATCHSIZE.name);
    if (!matchStr.empty()) {
        matchSize = (matchStr == "true" || matchStr == "1");
    }
    if (parser.hasNext()) parser.nextElement();
    try {
        initializeEntries();
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("XmlParseException: ") + e.what());
    }
}

} // namespace ghidra
