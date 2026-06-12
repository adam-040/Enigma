/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/DatatypeMatchFilter.h>
#include <ghidra/Encoder.h>
#include <ghidra/XmlPullParser.h>
#include <ghidra/ElementId.h>
#include <ghidra/AttributeId.h>
#include <ghidra/PrototypePieces.h>

namespace ghidra {

DatatypeMatchFilter::DatatypeMatchFilter()
    : position(-1), typeFilter(nullptr) {
}

DatatypeMatchFilter::~DatatypeMatchFilter() {
    delete typeFilter;
}

QualifierFilter* DatatypeMatchFilter::clone() const {
    auto* res = new DatatypeMatchFilter();
    res->position = position;
    if (typeFilter) {
        res->typeFilter = typeFilter->clone();
    }
    return res;
}

bool DatatypeMatchFilter::isEquivalent(const QualifierFilter& op) const {
    const auto* other = dynamic_cast<const DatatypeMatchFilter*>(&op);
    if (!other) return false;
    if (position != other->position) return false;
    if (typeFilter && other->typeFilter) {
        return typeFilter->isEquivalent(*other->typeFilter);
    }
    return typeFilter == other->typeFilter;
}

bool DatatypeMatchFilter::filter(const PrototypePieces& proto, int pos) {
    DataType* dt;
    if (position < 0) {
        dt = proto.outtype;
    } else {
        if (position >= static_cast<int>(proto.intypes.size())) {
            return false;
        }
        dt = proto.intypes[position];
    }
    return typeFilter && typeFilter->filter(dt);
}

void DatatypeMatchFilter::encode(Encoder& encoder) {
    encoder.openElement(ELEM_DATATYPE_AT);
    encoder.writeSignedInteger(ATTRIB_INDEX, position);
    if (typeFilter) {
        typeFilter->encode(encoder);
    }
    encoder.closeElement(ELEM_DATATYPE_AT);
}

void DatatypeMatchFilter::restoreXml(XmlPullParser& parser) {
    XmlElement elem = parser.nextElement();
    std::string posStr = elem.getAttribute(ATTRIB_INDEX.name);
    if (!posStr.empty()) {
        position = std::stoi(posStr);
    }
    if (typeFilter) {
        delete typeFilter;
        typeFilter = nullptr;
    }
    typeFilter = DatatypeFilter::restoreFilterXml(parser);
    if (parser.hasNext()) parser.nextElement();
}

} // namespace ghidra
