/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file InjectPayloadSubtypes.cpp
#include "ghidra/InjectPayloadSubtypes.h"
#include "ghidra/AddressFactory.h"
#include "ghidra/AddressSpace.h"

namespace ghidra {

InjectPayloadCallfixup::InjectPayloadCallfixup(const std::string& sourceName)
    : InjectPayloadSleigh(sourceName, InjectPayload::CALLFIXUP_TYPE, sourceName) {
    name = sourceName;
}

InjectPayloadCallfixup::InjectPayloadCallfixup(ConstructTpl* pcode, const std::string& nm)
    : InjectPayloadSleigh(nm, InjectPayload::CALLFIXUP_TYPE, nm) {
    (void)pcode;
}

InjectPayloadCallfixup::InjectPayloadCallfixup(ConstructTpl* pcode, InjectPayloadCallfixup* failed)
    : InjectPayloadSleigh(failed->getName(), InjectPayload::CALLFIXUP_TYPE, failed->getSource()) {
    (void)pcode;
    if (failed != nullptr) targetSymbolNames = failed->targetSymbolNames;
}

void InjectPayloadCallfixup::encode(Encoder& encoder) {
    encoder.openElement(ELEM_CALLFIXUP);
    encoder.writeString(ATTRIB_NAME, name);
    for (const auto& nm : targetSymbolNames) {
        encoder.openElement(ELEM_TARGET);
        encoder.writeString(ATTRIB_NAME, nm);
        encoder.closeElement(ELEM_TARGET);
    }
    InjectPayloadSleigh::encode(encoder);
    encoder.closeElement(ELEM_CALLFIXUP);
}

void InjectPayloadCallfixup::restoreXml(XmlPullParser* parser, SleighLanguage* language) {
    (void)parser; (void)language;
}

bool InjectPayloadCallfixup::isEquivalent(const InjectPayload* obj) const {
    if (obj == nullptr) return false;
    auto* op2 = dynamic_cast<const InjectPayloadCallfixup*>(obj);
    if (op2 == nullptr) return false;
    return targetSymbolNames == op2->targetSymbolNames;
}

InjectPayloadCallother::InjectPayloadCallother(const std::string& sourceName)
    : InjectPayloadSleigh(sourceName, InjectPayload::CALLOTHERFIXUP_TYPE, sourceName) {
    name = sourceName;
}

InjectPayloadCallother::InjectPayloadCallother(ConstructTpl* pcode, const std::string& nm)
    : InjectPayloadSleigh(nm, InjectPayload::CALLOTHERFIXUP_TYPE, nm) {
    (void)pcode;
}

InjectPayloadCallother::InjectPayloadCallother(ConstructTpl* pcode, InjectPayloadCallother* failed)
    : InjectPayloadSleigh(failed->getName(), InjectPayload::CALLOTHERFIXUP_TYPE, failed->getSource()) {
    (void)pcode;
}

void InjectPayloadCallother::encode(Encoder& encoder) {
    encoder.openElement(ELEM_CALLOTHERFIXUP);
    encoder.writeString(ATTRIB_TARGETOP, name);
    InjectPayloadSleigh::encode(encoder);
    encoder.closeElement(ELEM_CALLOTHERFIXUP);
}

void InjectPayloadCallother::restoreXml(XmlPullParser* parser, SleighLanguage* language) {
    (void)parser; (void)language;
}

InjectPayloadJumpAssist::InjectPayloadJumpAssist(const std::string& bName, const std::string& sourceName)
    : InjectPayloadSleigh(sourceName, InjectPayload::EXECUTABLEPCODE_TYPE, sourceName), baseName(bName) {}

void InjectPayloadJumpAssist::restoreXml(XmlPullParser* parser, SleighLanguage* language) {
    (void)parser; (void)language;
}

bool InjectPayloadJumpAssist::isEquivalent(const InjectPayload* obj) const {
    if (obj == nullptr) return false;
    auto* op2 = dynamic_cast<const InjectPayloadJumpAssist*>(obj);
    if (op2 == nullptr) return false;
    return baseName == op2->baseName;
}

InjectPayloadSegment::InjectPayloadSegment(const std::string& source)
    : InjectPayloadSleigh(source, InjectPayload::EXECUTABLEPCODE_TYPE, source),
      space(nullptr), supportsFarPointer(false),
      constResolveSpace(nullptr), constResolveOffset(0), constResolveSize(0) {}

void InjectPayloadSegment::encode(Encoder& encoder) {
    encoder.openElement(ELEM_SEGMENTOP);
    size_t pos = name.find('_');
    std::string subName = (pos != std::string::npos) ? name.substr(0, pos) : name;
    if (subName != "segment") {
        encoder.writeString(ATTRIB_USEROP, subName);
    }
    encoder.writeSpace(ATTRIB_SPACE, space);
    if (supportsFarPointer) {
        encoder.writeBool(ATTRIB_FARPOINTER, supportsFarPointer);
    }
    InjectPayloadSleigh::encode(encoder);
    if (constResolveSpace != nullptr) {
        encoder.openElement(ELEM_CONSTRESOLVE);
        encoder.openElement(ELEM_VARNODE);
        encoder.writeSpace(ATTRIB_SPACE, constResolveSpace);
        encoder.writeUnsignedInteger(ATTRIB_OFFSET, constResolveOffset);
        encoder.writeSignedInteger(ATTRIB_SIZE, constResolveSize);
        encoder.closeElement(ELEM_VARNODE);
        encoder.closeElement(ELEM_CONSTRESOLVE);
    }
    encoder.closeElement(ELEM_SEGMENTOP);
}

void InjectPayloadSegment::restoreXml(XmlPullParser* parser, SleighLanguage* language) {
    (void)parser; (void)language;
}

bool InjectPayloadSegment::isEquivalent(const InjectPayload* obj) const {
    if (obj == nullptr) return false;
    auto* op2 = dynamic_cast<const InjectPayloadSegment*>(obj);
    if (op2 == nullptr) return false;
    if (constResolveOffset != op2->constResolveOffset) return false;
    if (constResolveSize != op2->constResolveSize) return false;
    if (constResolveSpace != op2->constResolveSpace) return false;
    if (space != op2->space) return false;
    if (supportsFarPointer != op2->supportsFarPointer) return false;
    return true;
}

InjectPayloadCallfixupError::InjectPayloadCallfixupError(AddressFactory*,
                                                        InjectPayloadCallfixup* failedPayload)
    : InjectPayloadCallfixup(static_cast<ConstructTpl*>(nullptr), failedPayload) {}

InjectPayloadCallfixupError::InjectPayloadCallfixupError(AddressFactory*, const std::string& nm)
    : InjectPayloadCallfixup(static_cast<ConstructTpl*>(nullptr), nm) {}

InjectPayloadCallotherError::InjectPayloadCallotherError(AddressFactory*,
                                                        InjectPayloadCallother* failedPayload)
    : InjectPayloadCallother(static_cast<ConstructTpl*>(nullptr), failedPayload) {}

InjectPayloadCallotherError::InjectPayloadCallotherError(AddressFactory*, const std::string& nm)
    : InjectPayloadCallother(static_cast<ConstructTpl*>(nullptr), nm) {}

} // namespace ghidra
