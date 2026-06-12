/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file InjectPayloadSubtypes.h
/// \brief Subtypes of InjectPayloadSleigh: Callfixup, Callother, JumpAssist, Segment,
///        and their Error placeholders.
/// Translated from: ghidra.program.model.lang.InjectPayload{Callfixup,Callother,JumpAssist,Segment,...}
#pragma once

#include "ghidra/InjectPayloadSleigh.h"
#include "ghidra/AddressSpace.h"
#include <vector>
#include <string>

namespace ghidra {

class ConstructTpl;
class AddressFactory;

class InjectPayloadCallfixup : public InjectPayloadSleigh {
public:
    InjectPayloadCallfixup(const std::string& sourceName);
    InjectPayloadCallfixup(ConstructTpl* pcode, const std::string& nm);
    InjectPayloadCallfixup(ConstructTpl* pcode, InjectPayloadCallfixup* failedPayload);

    const std::vector<std::string>& getTargets() const { return targetSymbolNames; }
    void addTarget(const std::string& nm) { targetSymbolNames.push_back(nm); }

    void encode(Encoder& encoder) override;
    void restoreXml(XmlPullParser* parser, SleighLanguage* language) override;
    bool isEquivalent(const InjectPayload* obj) const override;

private:
    std::vector<std::string> targetSymbolNames;
};

class InjectPayloadCallother : public InjectPayloadSleigh {
public:
    InjectPayloadCallother(const std::string& sourceName);
    InjectPayloadCallother(ConstructTpl* pcode, const std::string& nm);
    InjectPayloadCallother(ConstructTpl* pcode, InjectPayloadCallother* failedPayload);

    void encode(Encoder& encoder) override;
    void restoreXml(XmlPullParser* parser, SleighLanguage* language) override;
};

class InjectPayloadJumpAssist : public InjectPayloadSleigh {
public:
    InjectPayloadJumpAssist(const std::string& bName, const std::string& sourceName);

    void restoreXml(XmlPullParser* parser, SleighLanguage* language) override;
    bool isEquivalent(const InjectPayload* obj) const override;

private:
    std::string baseName;
};

class InjectPayloadSegment : public InjectPayloadSleigh {
public:
    InjectPayloadSegment(const std::string& source);

    void encode(Encoder& encoder) override;
    void restoreXml(XmlPullParser* parser, SleighLanguage* language) override;
    bool isEquivalent(const InjectPayload* obj) const override;

    void setSpace(AddressSpace* spc) { space = spc; }
    AddressSpace* getSpace() const { return space; }
    void setSupportsFarPointer(bool v) { supportsFarPointer = v; }
    bool getSupportsFarPointer() const { return supportsFarPointer; }
    void setConstResolve(AddressSpace* spc, uint64_t offset, int size) {
        constResolveSpace = spc; constResolveOffset = offset; constResolveSize = size;
    }

private:
    AddressSpace* space;
    bool supportsFarPointer;
    AddressSpace* constResolveSpace;
    uint64_t constResolveOffset;
    int constResolveSize;
};

class InjectPayloadCallfixupError : public InjectPayloadCallfixup {
public:
    InjectPayloadCallfixupError(AddressFactory* addrFactory,
                                InjectPayloadCallfixup* failedPayload);
    InjectPayloadCallfixupError(AddressFactory* addrFactory, const std::string& nm);

    bool isErrorPlaceholder() const override { return true; }
};

class InjectPayloadCallotherError : public InjectPayloadCallother {
public:
    InjectPayloadCallotherError(AddressFactory* addrFactory,
                                InjectPayloadCallother* failedPayload);
    InjectPayloadCallotherError(AddressFactory* addrFactory, const std::string& nm);

    bool isErrorPlaceholder() const override { return true; }
};

} // namespace ghidra
