/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/MultiSlotAssign.h>
#include <ghidra/Encoder.h>
#include <ghidra/XmlPullParser.h>
#include <ghidra/ElementId.h>
#include <ghidra/AttributeId.h>
#include <ghidra/ParamListStandard.h>
#include <ghidra/ParamEntry.h>
#include <ghidra/Varnode.h>
#include <stdexcept>

namespace ghidra {

void MultiSlotAssign::initializeEntries() {
    std::vector<ParamEntry> tmp = resource->extractTiles(resourceType);
    tiles.clear();
    for (auto& entry : tmp) {
        tiles.push_back(&entry);
    }
    stackEntry = resource->extractStack();
    if (tiles.empty()) {
        throw std::runtime_error("Could not find matching resources for action: join");
    }
    if (consumeFromStack && stackEntry == nullptr) {
        throw std::runtime_error("Cannot find matching <pentry> for action: join");
    }
}

MultiSlotAssign::MultiSlotAssign(ParamListStandard* res)
    : AssignAction(res) {
    isBigEndian = res->isBigEndian();
    resourceType = StorageClass::GENERAL;
    consumeFromStack = true;
    consumeMostSig = false;
    enforceAlignment = false;
    justifyRight = false;
    adjacentEntries = true;
    allowBackfill = false;
    if (isBigEndian) {
        consumeMostSig = true;
        justifyRight = true;
    }
    stackEntry = nullptr;
}

MultiSlotAssign::MultiSlotAssign(StorageClass store, bool stack, bool mostSig, bool align,
                                 bool justRight, bool backfill, ParamListStandard* res)
    : AssignAction(res) {
    isBigEndian = res->isBigEndian();
    resourceType = store;
    consumeFromStack = stack;
    consumeMostSig = mostSig;
    enforceAlignment = align;
    justifyRight = justRight;
    adjacentEntries = true;
    allowBackfill = backfill;
    stackEntry = nullptr;
    initializeEntries();
}

AssignAction* MultiSlotAssign::clone(ParamListStandard* newResource) {
    return new MultiSlotAssign(resourceType, consumeFromStack, consumeMostSig, enforceAlignment,
                               justifyRight, allowBackfill, newResource);
}

bool MultiSlotAssign::isEquivalent(const AssignAction& op) const {
    const auto* other = dynamic_cast<const MultiSlotAssign*>(&op);
    if (!other) return false;
    if (consumeFromStack != other->consumeFromStack ||
        consumeMostSig != other->consumeMostSig ||
        enforceAlignment != other->enforceAlignment ||
        justifyRight != other->justifyRight ||
        adjacentEntries != other->adjacentEntries ||
        allowBackfill != other->allowBackfill) {
        return false;
    }
    if (resourceType != other->resourceType) return false;
    if (tiles.size() != other->tiles.size()) return false;
    for (size_t i = 0; i < tiles.size(); ++i) {
        if (!tiles[i]->isEquivalent(*other->tiles[i])) return false;
    }
    if (stackEntry == nullptr && other->stackEntry == nullptr) {
        // nothing
    } else if (stackEntry != nullptr && other->stackEntry != nullptr) {
        if (!stackEntry->isEquivalent(*other->stackEntry)) return false;
    } else {
        return false;
    }
    return true;
}

bool MultiSlotAssign::checkFit(int iter, int sizeLeft, int align, int resourcesConsumed, int* tmpStatus) {
    if (iter >= (int)tiles.size()) return false;
    ParamEntry* entry = tiles[iter];
    if (tmpStatus[entry->getGroup()] != 0) return false;
    if (enforceAlignment) {
        int regSize = entry->getSize();
        if (align > regSize && (resourcesConsumed % align) != 0) return false;
    }
    if (!adjacentEntries) return true;
    while (iter < (int)tiles.size() && sizeLeft > 0) {
        entry = tiles[iter];
        if (tmpStatus[entry->getGroup()] != 0) return false;
        sizeLeft -= entry->getSize();
        ++iter;
    }
    return true;
}

int MultiSlotAssign::assignAddress(DataType* dt, const PrototypePieces& proto, int pos,
                                   DataTypeManager* dtManager, int* status, ParameterPieces& res) {
    int sizeLeft = dt->getLength();
    int align = dt->getAlignment();
    int iter = 0;
    int resourcesConsumed = 0;
    while (iter < (int)tiles.size()) {
        if (checkFit(iter, sizeLeft, align, resourcesConsumed, status)) {
            break;
        }
        ParamEntry* entry = tiles[iter];
        if (!allowBackfill) {
            status[entry->getGroup()] = -1;
        }
        resourcesConsumed += entry->getSize();
        ++iter;
    }
    while (sizeLeft > 0 && iter < (int)tiles.size()) {
        ParamEntry* entry = tiles[iter];
        ++iter;
        if (status[entry->getGroup()] != 0) continue;
        int trialSize = entry->getSize();
        ParameterPieces param;
        entry->getAddrBySlot(status[entry->getGroup()], trialSize, align, param);
        status[entry->getGroup()] = -1;
        sizeLeft -= trialSize;
        align = 1;
    }
    if (sizeLeft > 0) {
        if (!consumeFromStack) return FAIL;
        int grp = stackEntry->getGroup();
        ParameterPieces param;
        status[grp] = stackEntry->getAddrBySlot(status[grp], sizeLeft, align, param, justifyRight);
        if (param.address.getAddressSpace() == nullptr) return FAIL;
    }
    if (sizeLeft < 0) {
        if (resourceType == StorageClass::FLOAT && tiles.size() == 1) {
            // One-piece join for float
        } else {
            // justifyPieces would be called here
        }
    }
    res.type = dt;
    return SUCCESS;
}

void MultiSlotAssign::encode(Encoder& encoder) {
    encoder.openElement(ELEM_JOIN);
    if (resource->isBigEndian() != justifyRight) {
        encoder.writeBool(ATTRIB_REVERSEJUSTIFY, true);
    }
    if (resource->isBigEndian() != consumeMostSig) {
        encoder.writeBool(ATTRIB_REVERSESIGNIF, true);
    }
    if (resourceType != StorageClass::GENERAL) {
        encoder.writeString(ATTRIB_STORAGE, toString(resourceType));
    }
    encoder.writeBool(ATTRIB_ALIGN, enforceAlignment);
    encoder.writeBool(ATTRIB_STACKSPILL, consumeFromStack);
    encoder.writeBool(ATTRIB_BACKFILL, allowBackfill);
    encoder.closeElement(ELEM_JOIN);
}

void MultiSlotAssign::restoreXml(XmlPullParser& parser) {
    XmlElement elem = parser.nextElement();
    std::string revJustStr = elem.getAttribute(ATTRIB_REVERSEJUSTIFY.name);
    if (revJustStr == "true" || revJustStr == "1") {
        justifyRight = !justifyRight;
    }
    std::string revSigStr = elem.getAttribute(ATTRIB_REVERSESIGNIF.name);
    if (revSigStr == "true" || revSigStr == "1") {
        consumeMostSig = !consumeMostSig;
    }
    std::string storageStr = elem.getAttribute(ATTRIB_STORAGE.name);
    if (!storageStr.empty()) {
        resourceType = storageClassFromString(storageStr);
    }
    std::string alignStr = elem.getAttribute(ATTRIB_ALIGN.name);
    if (!alignStr.empty()) {
        enforceAlignment = (alignStr == "true" || alignStr == "1");
    }
    std::string stackStr = elem.getAttribute(ATTRIB_STACKSPILL.name);
    if (!stackStr.empty()) {
        consumeFromStack = (stackStr == "true" || stackStr == "1");
    }
    std::string backStr = elem.getAttribute(ATTRIB_BACKFILL.name);
    if (!backStr.empty()) {
        allowBackfill = (backStr == "true" || backStr == "1");
    }
    if (parser.hasNext()) parser.nextElement();
    try {
        initializeEntries();
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("XmlParseException: ") + e.what());
    }
}

} // namespace ghidra
