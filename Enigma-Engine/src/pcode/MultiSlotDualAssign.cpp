/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/MultiSlotDualAssign.h>
#include <ghidra/Encoder.h>
#include <ghidra/XmlPullParser.h>
#include <ghidra/ElementId.h>
#include <ghidra/AttributeId.h>
#include <ghidra/ParamListStandard.h>
#include <ghidra/ParamEntry.h>
#include <ghidra/PrimitiveExtractor.h>
#include <ghidra/Metatype.h>
#include <stdexcept>

namespace ghidra {

void MultiSlotDualAssign::initializeEntries() {
    std::vector<ParamEntry> tmpBase = resource->extractTiles(baseType);
    baseTiles.clear();
    for (auto& entry : tmpBase) {
        baseTiles.push_back(&entry);
    }
    std::vector<ParamEntry> tmpAlt = resource->extractTiles(altType);
    altTiles.clear();
    for (auto& entry : tmpAlt) {
        altTiles.push_back(&entry);
    }
    stackEntry = resource->extractStack();
    if (baseTiles.empty() || altTiles.empty()) {
        throw std::runtime_error("Could not find matching resources for action: join_dual_class");
    }
    tileSize = baseTiles[0]->getSize();
    if (tileSize != altTiles[0]->getSize()) {
        throw std::runtime_error("Storage class register sizes do not match for action: join_dual_class");
    }
    if (consumeFromStack && stackEntry == nullptr) {
        throw std::runtime_error("Cannot find matching stack resource for action: join_dual_class");
    }
}

int MultiSlotDualAssign::getFirstUnused(int iter, std::vector<ParamEntry*>& tiles, int* status) {
    for (; iter < (int)tiles.size(); ++iter) {
        if (status[tiles[iter]->getGroup()] != 0) continue;
        return iter;
    }
    return (int)tiles.size();
}

int MultiSlotDualAssign::getTileClass(PrimitiveExtractor& primitives, int off, int* index) {
    int res = 1;
    int count = 0;
    int endBoundary = off + tileSize;
    if (index[0] >= primitives.size()) return -1;
    auto& firstPrimitive = primitives.get(index[0]);
    while (index[0] < primitives.size()) {
        auto& element = primitives.get(index[0]);
        if (element.offset < off) return -1;
        if (element.offset >= endBoundary) break;
        if (element.offset + element.dt->getLength() > endBoundary) return -1;
        count += 1;
        index[0] += 1;
        StorageClass storage = ParamEntry::getBasicTypeClass(element.dt);
        if (storage != altType) res = 0;
    }
    if (count == 0) return -1;
    if (fillAlternate) {
        if (count > 1) res = 0;
        if (firstPrimitive.dt->getLength() != tileSize) res = 0;
    }
    return res;
}

MultiSlotDualAssign::MultiSlotDualAssign(ParamListStandard* res)
    : AssignAction(res) {
    isBigEndian = res->isBigEndian();
    baseType = StorageClass::GENERAL;
    altType = StorageClass::FLOAT;
    consumeFromStack = false;
    consumeMostSig = false;
    justifyRight = false;
    if (isBigEndian) {
        consumeMostSig = true;
        justifyRight = true;
    }
    fillAlternate = false;
    tileSize = 0;
    stackEntry = nullptr;
}

MultiSlotDualAssign::MultiSlotDualAssign(StorageClass baseStore, StorageClass altStore, bool stack,
                                         bool mostSig, bool justRight, bool fillAlt,
                                         ParamListStandard* res)
    : AssignAction(res) {
    isBigEndian = res->isBigEndian();
    baseType = baseStore;
    altType = altStore;
    consumeFromStack = stack;
    consumeMostSig = mostSig;
    justifyRight = justRight;
    fillAlternate = fillAlt;
    stackEntry = nullptr;
    initializeEntries();
}

AssignAction* MultiSlotDualAssign::clone(ParamListStandard* newResource) {
    return new MultiSlotDualAssign(baseType, altType, consumeFromStack, consumeMostSig,
                                   justifyRight, fillAlternate, newResource);
}

bool MultiSlotDualAssign::isEquivalent(const AssignAction& op) const {
    const auto* other = dynamic_cast<const MultiSlotDualAssign*>(&op);
    if (!other) return false;
    if (consumeFromStack != other->consumeFromStack ||
        consumeMostSig != other->consumeMostSig ||
        justifyRight != other->justifyRight ||
        fillAlternate != other->fillAlternate) {
        return false;
    }
    if (baseType != other->baseType || altType != other->altType) return false;
    if (baseTiles.size() != other->baseTiles.size()) return false;
    for (size_t i = 0; i < baseTiles.size(); ++i) {
        if (!baseTiles[i]->isEquivalent(*other->baseTiles[i])) return false;
    }
    if (altTiles.size() != other->altTiles.size()) return false;
    for (size_t i = 0; i < altTiles.size(); ++i) {
        if (!altTiles[i]->isEquivalent(*other->altTiles[i])) return false;
    }
    return true;
}

int MultiSlotDualAssign::assignAddress(DataType* dt, const PrototypePieces& proto, int pos,
                                       DataTypeManager* dtManager, int* status, ParameterPieces& res) {
    PrimitiveExtractor primitives(dt, false, 0, 1024);
    if (!primitives.isValid() || primitives.size() == 0 || primitives.containsHoles()) {
        return FAIL;
    }
    int typeSize = dt->getLength();
    int align = dt->getAlignment();
    int sizeLeft = typeSize;
    int iterBase = 0;
    int iterAlt = 0;
    while (sizeLeft > 0) {
        int primIndex = typeSize - sizeLeft;
        int tileClass = getTileClass(primitives, primIndex, &primIndex);
        if (tileClass < 0) return FAIL;
        if (tileClass == 0) {
            iterBase = getFirstUnused(iterBase, baseTiles, status);
            if (iterBase == (int)baseTiles.size()) {
                if (!consumeFromStack) return FAIL;
                break;
            }
            ParamEntry* entry = baseTiles[iterBase];
            int trialSize = entry->getSize();
            ParameterPieces param;
            entry->getAddrBySlot(status[entry->getGroup()], trialSize, 1, param);
            status[entry->getGroup()] = -1;
            sizeLeft -= trialSize;
        } else {
            iterAlt = getFirstUnused(iterAlt, altTiles, status);
            if (iterAlt == (int)altTiles.size()) {
                if (!consumeFromStack) return FAIL;
                break;
            }
            ParamEntry* entry = altTiles[iterAlt];
            int trialSize = entry->getSize();
            ParameterPieces param;
            entry->getAddrBySlot(status[entry->getGroup()], trialSize, 1, param);
            status[entry->getGroup()] = -1;
            sizeLeft -= trialSize;
        }
    }
    if (sizeLeft > 0) {
        if (!consumeFromStack) return FAIL;
        int grp = stackEntry->getGroup();
        ParameterPieces param;
        status[grp] = stackEntry->getAddrBySlot(status[grp], sizeLeft, align, param, justifyRight);
        if (param.address.getAddressSpace() == nullptr) return FAIL;
    }
    if (sizeLeft < 0) {
        // justifyPieces would be called here
    }
    res.type = dt;
    return SUCCESS;
}

void MultiSlotDualAssign::encode(Encoder& encoder) {
    encoder.openElement(ELEM_JOIN_DUAL_CLASS);
    if (resource->isBigEndian() != justifyRight) {
        encoder.writeBool(ATTRIB_REVERSEJUSTIFY, true);
    }
    if (resource->isBigEndian() != consumeMostSig) {
        encoder.writeBool(ATTRIB_REVERSESIGNIF, true);
    }
    if (baseType != StorageClass::GENERAL) {
        encoder.writeString(ATTRIB_STORAGE, toString(baseType));
    }
    if (altType != StorageClass::FLOAT) {
        encoder.writeString(ATTRIB_B, toString(altType));
    }
    encoder.writeBool(ATTRIB_STACKSPILL, consumeFromStack);
    encoder.writeBool(ATTRIB_FILL_ALTERNATE, fillAlternate);
    encoder.closeElement(ELEM_JOIN_DUAL_CLASS);
}

void MultiSlotDualAssign::restoreXml(XmlPullParser& parser) {
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
    if (storageStr.empty()) {
        storageStr = elem.getAttribute(ATTRIB_A.name);
    }
    if (!storageStr.empty()) {
        baseType = storageClassFromString(storageStr);
    }
    std::string altStr = elem.getAttribute(ATTRIB_B.name);
    if (!altStr.empty()) {
        altType = storageClassFromString(altStr);
    }
    std::string stackStr = elem.getAttribute(ATTRIB_STACKSPILL.name);
    if (!stackStr.empty()) {
        consumeFromStack = (stackStr == "true" || stackStr == "1");
    }
    std::string fillStr = elem.getAttribute(ATTRIB_FILL_ALTERNATE.name);
    if (!fillStr.empty()) {
        fillAlternate = (fillStr == "true" || fillStr == "1");
    }
    if (parser.hasNext()) parser.nextElement();
    try {
        initializeEntries();
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("XmlParseException: ") + e.what());
    }
}

} // namespace ghidra
