/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/PositionMatchFilter.h>
#include <ghidra/Encoder.h>
#include <ghidra/XmlPullParser.h>
#include <ghidra/ElementId.h>
#include <ghidra/AttributeId.h>

namespace ghidra {

PositionMatchFilter::PositionMatchFilter(int pos)
    : position(pos) {
}

QualifierFilter* PositionMatchFilter::clone() const {
    return new PositionMatchFilter(position);
}

bool PositionMatchFilter::isEquivalent(const QualifierFilter& op) const {
    const auto* other = dynamic_cast<const PositionMatchFilter*>(&op);
    if (!other) return false;
    return position == other->position;
}

bool PositionMatchFilter::filter(const PrototypePieces& proto, int pos) {
    return pos == position;
}

void PositionMatchFilter::encode(Encoder& encoder) {
    encoder.openElement(ELEM_POSITION);
    encoder.writeSignedInteger(ATTRIB_INDEX, position);
    encoder.closeElement(ELEM_POSITION);
}

void PositionMatchFilter::restoreXml(XmlPullParser& parser) {
    XmlElement elem = parser.nextElement();
    std::string posStr = elem.getAttribute(ATTRIB_INDEX.name);
    if (!posStr.empty()) {
        position = std::stoi(posStr);
    }
    if (parser.hasNext()) parser.nextElement();
}

} // namespace ghidra
