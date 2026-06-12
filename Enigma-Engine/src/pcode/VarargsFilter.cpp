/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/VarargsFilter.h>
#include <ghidra/Encoder.h>
#include <ghidra/XmlPullParser.h>
#include <ghidra/ElementId.h>
#include <ghidra/AttributeId.h>
#include <climits>

namespace ghidra {

VarargsFilter::VarargsFilter()
    : firstPos(INT_MIN), lastPos(INT_MAX) {
}

VarargsFilter::VarargsFilter(int first, int last)
    : firstPos(first), lastPos(last) {
}

QualifierFilter* VarargsFilter::clone() const {
    return new VarargsFilter(firstPos, lastPos);
}

bool VarargsFilter::isEquivalent(const QualifierFilter& op) const {
    const auto* other = dynamic_cast<const VarargsFilter*>(&op);
    if (!other) return false;
    return firstPos == other->firstPos && lastPos == other->lastPos;
}

bool VarargsFilter::filter(const PrototypePieces& proto, int pos) {
    if (proto.firstVarArgSlot < 0) {
        return false;
    }
    pos -= proto.firstVarArgSlot;
    return pos >= firstPos && pos <= lastPos;
}

void VarargsFilter::encode(Encoder& encoder) {
    encoder.openElement(ELEM_VARARGS);
    if (firstPos != INT_MIN) {
        encoder.writeSignedInteger(ATTRIB_FIRST, firstPos);
    }
    if (lastPos != INT_MAX) {
        encoder.writeSignedInteger(ATTRIB_LAST, lastPos);
    }
    encoder.closeElement(ELEM_VARARGS);
}

void VarargsFilter::restoreXml(XmlPullParser& parser) {
    XmlElement elem = parser.nextElement();
    std::string firstStr = elem.getAttribute(ATTRIB_FIRST.name);
    if (!firstStr.empty()) {
        firstPos = std::stoi(firstStr);
    }
    std::string lastStr = elem.getAttribute(ATTRIB_LAST.name);
    if (!lastStr.empty()) {
        lastPos = std::stoi(lastStr);
    }
    if (parser.hasNext()) parser.nextElement();
}

} // namespace ghidra
