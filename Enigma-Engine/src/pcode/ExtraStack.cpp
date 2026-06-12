/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/ExtraStack.h>
#include <ghidra/Encoder.h>
#include <ghidra/XmlPullParser.h>
#include <ghidra/ElementId.h>
#include <ghidra/AttributeId.h>
#include <ghidra/ParamListStandard.h>
#include <ghidra/ParamEntry.h>
#include <ghidra/AddressSpace.h>
#include <stdexcept>

namespace ghidra {

void ExtraStack::initializeEntry() {
    for (int i = 0; i < resource->getNumParamEntry(); ++i) {
        ParamEntry& entry = resource->getEntry(i);
        if (!entry.isExclusion() && entry.getSpace()->isStackSpace()) {
            stackEntry = &entry;
            return;
        }
    }
    throw std::runtime_error("Cannot find matching <pentry> for action: extra_stack");
}

ExtraStack::ExtraStack(ParamListStandard* res, int val)
    : AssignAction(res) {
    stackEntry = nullptr;
    afterStorage = StorageClass::GENERAL;
    afterBytes = -1;
}

ExtraStack::ExtraStack(StorageClass storage, int offset, ParamListStandard* res)
    : AssignAction(res) {
    stackEntry = nullptr;
    afterStorage = storage;
    afterBytes = offset;
    initializeEntry();
}

AssignAction* ExtraStack::clone(ParamListStandard* newResource) {
    return new ExtraStack(afterStorage, afterBytes, newResource);
}

bool ExtraStack::isEquivalent(const AssignAction& op) const {
    const auto* other = dynamic_cast<const ExtraStack*>(&op);
    if (!other) return false;
    if (afterBytes != other->afterBytes || afterStorage != other->afterStorage) return false;
    return stackEntry->isEquivalent(*other->stackEntry);
}

int ExtraStack::assignAddress(DataType* dt, const PrototypePieces& proto, int pos,
                              DataTypeManager* dtManager, int* status, ParameterPieces& res) {
    if (res.address.getAddressSpace() == stackEntry->getSpace()) {
        return SUCCESS;
    }
    int grp = stackEntry->getGroup();
    if (afterBytes > 0) {
        int bytesConsumed = 0;
        for (int i = 0; i < resource->getNumParamEntry(); i++) {
            if (i == grp || resource->getEntry(i).getType() != afterStorage) {
                continue;
            }
            if (status[i] != 0) {
                bytesConsumed += resource->getEntry(i).getSize();
            }
        }
        if (bytesConsumed < afterBytes) {
            return SUCCESS;
        }
    }
    ParameterPieces unused;
    status[grp] = stackEntry->getAddrBySlot(status[grp], dt->getLength(), dt->getAlignment(), unused);
    return SUCCESS;
}

void ExtraStack::encode(Encoder& encoder) {
    encoder.openElement(ELEM_EXTRA_STACK);
    if (afterBytes >= 0) {
        encoder.writeUnsignedInteger(ATTRIB_AFTER_BYTES, afterBytes);
    }
    if (afterStorage != StorageClass::GENERAL) {
        encoder.writeString(ATTRIB_STORAGE, toString(afterStorage));
    }
    encoder.closeElement(ELEM_EXTRA_STACK);
}

void ExtraStack::restoreXml(XmlPullParser& parser) {
    XmlElement elem = parser.nextElement();
    std::string afterBytesStr = elem.getAttribute(ATTRIB_AFTER_BYTES.name);
    if (!afterBytesStr.empty()) {
        afterBytes = std::stoi(afterBytesStr);
    }
    std::string storageStr = elem.getAttribute(ATTRIB_STORAGE.name);
    if (!storageStr.empty()) {
        afterStorage = storageClassFromString(storageStr);
    }
    if (parser.hasNext()) parser.nextElement();
    initializeEntry();
}

} // namespace ghidra
