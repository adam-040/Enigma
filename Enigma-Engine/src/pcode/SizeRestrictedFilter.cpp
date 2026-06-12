/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/SizeRestrictedFilter.h>
#include <ghidra/XmlPullParser.h>
#include <ghidra/AttributeId.h>
#include <ghidra/ElementId.h>
#include <algorithm>
#include <sstream>
#include <climits>

namespace ghidra {

SizeRestrictedFilter::SizeRestrictedFilter(int min, int max)
    : minSize(min), maxSize(max) {
    if (maxSize == 0 && minSize >= 0) {
        maxSize = INT_MAX;
    }
}

SizeRestrictedFilter::SizeRestrictedFilter(const SizeRestrictedFilter& op2)
    : minSize(op2.minSize), maxSize(op2.maxSize), sizes(op2.sizes) {
}

DatatypeFilter* SizeRestrictedFilter::clone() const {
    return new SizeRestrictedFilter(*this);
}

bool SizeRestrictedFilter::isEquivalent(const DatatypeFilter& op) const {
    const auto* otherFilter = dynamic_cast<const SizeRestrictedFilter*>(&op);
    if (!otherFilter) return false;
    if (maxSize != otherFilter->maxSize || minSize != otherFilter->minSize)
        return false;
    return sizes == otherFilter->sizes;
}

bool SizeRestrictedFilter::filter(DataType* dt) {
    return filterOnSize(dt);
}

bool SizeRestrictedFilter::filterOnSize(DataType* dt) const {
    if (maxSize == 0)
        return true;
    int len = dt->getLength();
    if (!sizes.empty())
        return sizes.find(len) != sizes.end();
    return len >= minSize && len <= maxSize;
}

void SizeRestrictedFilter::encode(Encoder& encoder) {
    encoder.openElement(ELEM_DATATYPE);
    encodeAttributes(encoder);
    encoder.closeElement(ELEM_DATATYPE);
}

void SizeRestrictedFilter::restoreXml(XmlPullParser& parser) {
    XmlElement elem = parser.nextElement();
    restoreAttributesXml(&elem);
    if (parser.hasNext()) parser.nextElement();
}

void SizeRestrictedFilter::encodeAttributes(Encoder& encoder) {
    if (maxSize != 0) {
        if (!sizes.empty()) {
            std::string sizesStr;
            for (auto it = sizes.begin(); it != sizes.end(); ++it) {
                if (it != sizes.begin()) sizesStr += ",";
                sizesStr += std::to_string(*it);
            }
            encoder.writeString(ATTRIB_SIZES, sizesStr);
        } else {
            encoder.writeSignedInteger(ATTRIB_MINSIZE, minSize);
            encoder.writeSignedInteger(ATTRIB_MAXSIZE, maxSize);
        }
    }
}

void SizeRestrictedFilter::restoreAttributesXml(XmlElement* el) {
    std::string maxSizeStr = el->getAttribute(ATTRIB_MAXSIZE.name);
    if (!maxSizeStr.empty()) {
        maxSize = std::stoi(maxSizeStr);
    }
    std::string minSizeStr = el->getAttribute(ATTRIB_MINSIZE.name);
    if (!minSizeStr.empty()) {
        minSize = std::stoi(minSizeStr);
    }
    std::string sizesStr = el->getAttribute(ATTRIB_SIZES.name);
    if (!sizesStr.empty()) {
        initFromSizeList(sizesStr);
    }
}

void SizeRestrictedFilter::initFromSizeList(const std::string& str) {
    std::string temp = str;
    // Replace commas with spaces for tokenization
    for (auto& c : temp) {
        if (c == ',') c = ' ';
    }
    std::istringstream stream(temp);
    std::string token;
    sizes.clear();
    minSize = INT_MAX;
    maxSize = 0;
    while (stream >> token) {
        int val = std::stoi(token);
        if (val <= 0)
            continue;
        sizes.insert(val);
        if (val < minSize) minSize = val;
        if (val > maxSize) maxSize = val;
    }
    if (sizes.empty()) {
        sizes.clear();
        minSize = 0;
        maxSize = 0;
    }
}

} // namespace ghidra
