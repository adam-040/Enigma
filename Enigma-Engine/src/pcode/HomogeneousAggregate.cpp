/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/HomogeneousAggregate.h>
#include <ghidra/Encoder.h>
#include <ghidra/XmlPullParser.h>
#include <ghidra/ElementId.h>
#include <ghidra/AttributeId.h>
#include <ghidra/Metatype.h>
#include <ghidra/PrimitiveExtractor.h>

namespace ghidra {

HomogeneousAggregate::HomogeneousAggregate(const std::string& nm, int meta)
    : SizeRestrictedFilter(), name(nm), metaType(meta), maxPrimitives(DEFAULT_MAX_PRIMITIVES) {
}

HomogeneousAggregate::HomogeneousAggregate(const std::string& nm, int meta, int maxPrim, int minSize, int maxSize)
    : SizeRestrictedFilter(minSize, maxSize), name(nm), metaType(meta), maxPrimitives(maxPrim) {
}

HomogeneousAggregate::HomogeneousAggregate(const HomogeneousAggregate& op2)
    : SizeRestrictedFilter(op2), name(op2.name), metaType(op2.metaType), maxPrimitives(op2.maxPrimitives) {
}

DatatypeFilter* HomogeneousAggregate::clone() const {
    return new HomogeneousAggregate(*this);
}

bool HomogeneousAggregate::isEquivalent(const DatatypeFilter& op) const {
    if (!SizeRestrictedFilter::isEquivalent(op)) return false;
    const auto* other = dynamic_cast<const HomogeneousAggregate*>(&op);
    if (!other) return false;
    return metaType == other->metaType && maxPrimitives == other->maxPrimitives;
}

bool HomogeneousAggregate::filter(DataType* dt) {
    int meta = Metatype::getMetatype(dt);
    if (meta != Metatype::TYPE_ARRAY && meta != Metatype::TYPE_STRUCT) return false;
    PrimitiveExtractor primitives(dt, true, 0, maxPrimitives);
    if (!primitives.isValid() || primitives.size() == 0 || primitives.containsUnknown() ||
        !primitives.isAligned() || primitives.containsHoles()) {
        return false;
    }
    DataType* base = primitives.get(0).dt;
    int baseMeta = Metatype::getMetatype(base);
    if (baseMeta != metaType) return false;
    for (int i = 1; i < primitives.size(); ++i) {
        if (primitives.get(i).dt != base) return false;
    }
    return true;
}

void HomogeneousAggregate::encodeAttributes(Encoder& encoder) {
    SizeRestrictedFilter::encodeAttributes(encoder);
    encoder.writeUnsignedInteger(ATTRIB_MAX_PRIMITIVES, maxPrimitives);
}

void HomogeneousAggregate::encode(Encoder& encoder) {
    encoder.openElement(ELEM_DATATYPE);
    encoder.writeString(ATTRIB_NAME, name);
    encodeAttributes(encoder);
    encoder.closeElement(ELEM_DATATYPE);
}

void HomogeneousAggregate::restoreAttributesXml(XmlElement* el) {
    SizeRestrictedFilter::restoreAttributesXml(el);
    std::string maxPrimStr = el->getAttribute(ATTRIB_MAX_PRIMITIVES.name);
    if (!maxPrimStr.empty()) {
        maxPrimitives = std::stoi(maxPrimStr);
    }
}

void HomogeneousAggregate::restoreXml(XmlPullParser& parser) {
    XmlElement elem = parser.nextElement();
    restoreAttributesXml(&elem);
    if (parser.hasNext()) parser.nextElement();
}

} // namespace ghidra
