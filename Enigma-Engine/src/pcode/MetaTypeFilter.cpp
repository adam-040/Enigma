/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/MetaTypeFilter.h>
#include <ghidra/Encoder.h>
#include <ghidra/XmlPullParser.h>
#include <ghidra/ElementId.h>
#include <ghidra/AttributeId.h>
#include <ghidra/Metatype.h>

namespace ghidra {

MetaTypeFilter::MetaTypeFilter(int meta)
    : SizeRestrictedFilter(), metaType(meta) {
}

MetaTypeFilter::MetaTypeFilter(int meta, int min, int max)
    : SizeRestrictedFilter(min, max), metaType(meta) {
}

MetaTypeFilter::MetaTypeFilter(const MetaTypeFilter& op2)
    : SizeRestrictedFilter(op2), metaType(op2.metaType) {
}

DatatypeFilter* MetaTypeFilter::clone() const {
    return new MetaTypeFilter(*this);
}

bool MetaTypeFilter::isEquivalent(const DatatypeFilter& op) const {
    if (!SizeRestrictedFilter::isEquivalent(op)) return false;
    const auto* other = dynamic_cast<const MetaTypeFilter*>(&op);
    if (!other) return false;
    return metaType == other->metaType;
}

bool MetaTypeFilter::filter(DataType* dt) {
    if (Metatype::getMetatype(dt) != metaType) return false;
    return filterOnSize(dt);
}

void MetaTypeFilter::encodeAttributes(Encoder& encoder) {
    SizeRestrictedFilter::encodeAttributes(encoder);
}

void MetaTypeFilter::encode(Encoder& encoder) {
    encoder.openElement(ELEM_DATATYPE);
    encoder.writeString(ATTRIB_NAME, Metatype::getMetatypeString(metaType));
    encodeAttributes(encoder);
    encoder.closeElement(ELEM_DATATYPE);
}

void MetaTypeFilter::restoreXml(XmlPullParser& parser) {
    XmlElement elem = parser.nextElement();
    std::string nameStr = elem.getAttribute(ATTRIB_NAME.name);
    if (!nameStr.empty()) {
        metaType = Metatype::getMetatypeFromString(nameStr);
    }
    restoreAttributesXml(&elem);
    if (parser.hasNext()) parser.nextElement();
}

} // namespace ghidra
