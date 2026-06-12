/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/AndFilter.h>
#include <algorithm>

namespace ghidra {

AndFilter::AndFilter(std::vector<QualifierFilter*>& qualifierList) {
    subQualifiers.resize(qualifierList.size());
    for (size_t i = 0; i < qualifierList.size(); ++i) {
        subQualifiers[i] = qualifierList[i]->clone();
    }
}

AndFilter::AndFilter(const AndFilter& op) {
    subQualifiers.resize(op.subQualifiers.size());
    for (size_t i = 0; i < subQualifiers.size(); ++i) {
        subQualifiers[i] = op.subQualifiers[i]->clone();
    }
}

AndFilter::~AndFilter() {
    for (auto* q : subQualifiers) {
        delete q;
    }
}

QualifierFilter* AndFilter::clone() const {
    return new AndFilter(*this);
}

bool AndFilter::isEquivalent(const QualifierFilter& op) const {
    const auto* otherFilter = dynamic_cast<const AndFilter*>(&op);
    if (!otherFilter) return false;
    if (subQualifiers.size() != otherFilter->subQualifiers.size())
        return false;
    for (size_t i = 0; i < subQualifiers.size(); ++i) {
        if (!subQualifiers[i]->isEquivalent(*otherFilter->subQualifiers[i]))
            return false;
    }
    return true;
}

bool AndFilter::filter(const PrototypePieces& proto, int pos) {
    for (auto* q : subQualifiers) {
        if (!q->filter(proto, pos))
            return false;
    }
    return true;
}

void AndFilter::encode(Encoder& encoder) {
    for (auto* q : subQualifiers) {
        q->encode(encoder);
    }
}

void AndFilter::restoreXml(class XmlPullParser& parser) {
    // Stub
}

} // namespace ghidra
