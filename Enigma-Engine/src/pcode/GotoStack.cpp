/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/GotoStack.h>
#include <ghidra/Encoder.h>
#include <ghidra/XmlPullParser.h>
#include <ghidra/ElementId.h>
#include <ghidra/ParamListStandard.h>
#include <ghidra/ParamEntry.h>
#include <ghidra/AddressSpace.h>
#include <stdexcept>

namespace ghidra {

void GotoStack::initializeEntry() {
    for (int i = 0; i < resource->getNumParamEntry(); ++i) {
        ParamEntry& entry = resource->getEntry(i);
        if (!entry.isExclusion() && entry.getSpace()->isStackSpace()) {
            stackEntry = &entry;
            return;
        }
    }
    throw std::runtime_error("Cannot find matching <pentry> for action: goto_stack");
}

GotoStack::GotoStack(ParamListStandard* res, int val)
    : AssignAction(res), stackEntry(nullptr) {
}

GotoStack::GotoStack(ParamListStandard* res)
    : AssignAction(res), stackEntry(nullptr) {
    initializeEntry();
}

AssignAction* GotoStack::clone(ParamListStandard* newResource) {
    return new GotoStack(newResource);
}

bool GotoStack::isEquivalent(const AssignAction& op) const {
    const auto* other = dynamic_cast<const GotoStack*>(&op);
    if (!other) return false;
    return stackEntry->isEquivalent(*other->stackEntry);
}

int GotoStack::assignAddress(DataType* dt, const PrototypePieces& proto, int pos,
                             DataTypeManager* dtManager, int* status, ParameterPieces& res) {
    int grp = stackEntry->getGroup();
    res.type = dt;
    status[grp] = stackEntry->getAddrBySlot(status[grp], dt->getLength(), dt->getAlignment(), res);
    return SUCCESS;
}

void GotoStack::encode(Encoder& encoder) {
    encoder.openElement(ELEM_GOTO_STACK);
    encoder.closeElement(ELEM_GOTO_STACK);
}

void GotoStack::restoreXml(XmlPullParser& parser) {
    XmlElement elem = parser.nextElement();
    // Consume end element
    if (parser.hasNext()) parser.nextElement();
    initializeEntry();
}

} // namespace ghidra
