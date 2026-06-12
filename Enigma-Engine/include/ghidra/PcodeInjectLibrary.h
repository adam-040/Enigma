/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once

#include <ghidra/InjectPayload.h>
#include <ghidra/UniqueLayout.h>
#include <ghidra/SleighException.h>
#include <ghidra/InjectPayloadSleigh.h>
#include <string>
#include <vector>
#include <map>
#include <list>

namespace ghidra {

class SleighLanguage;
class InjectPayloadSleigh;
class Program;
class ConstantPool;
class XmlPullParser;
class ConstructTpl;

class PcodeInjectLibrary {
public:
    PcodeInjectLibrary(SleighLanguage* lang);
    PcodeInjectLibrary(const PcodeInjectLibrary& other);
    PcodeInjectLibrary* clone() const { return new PcodeInjectLibrary(*this); }

    SleighLanguage* getLanguage() const { return language_; }
    long getUniqueBase() const { return uniqueBase_; }

    std::vector<InjectPayloadSleigh*> getProgramPayloads() const { return programPayload_; }
    bool hasProgramPayload(const std::string& nm, int type) const;

    bool isOverride(const std::string& nm, int type) const;

    InjectPayload* getPayload(int type, const std::string& name) const;

    void parseInject(InjectPayload* payload);

    std::vector<std::string> getCallFixupNames() const;
    std::vector<std::string> getCallotherFixupNames() const;

    InjectContext* buildInjectContext();

    bool hasUserDefinedOp(const std::string& name);
    void registerInject(InjectPayload* payload);
    bool removeMechanismPayload(const std::string& nm);
    void uninstallProgramPayloads();
    void registerProgramInject(std::vector<InjectPayloadSleigh*>& userPayloads);

    virtual InjectPayload* allocateInject(const std::string& sourceName,
                                          const std::string& name, int tp);

    void encodeCompilerSpec(Encoder& encoder);
    InjectPayload* restoreXmlInject(const std::string& source, const std::string& name,
                                    int tp, XmlPullParser* parser);

    virtual ConstantPool* getConstantPool(Program* program);

    bool isEquivalent(const PcodeInjectLibrary* obj) const;

protected:
    SleighLanguage* language_;
    long uniqueBase_ = 0;

private:
    using PayloadMap = std::map<std::string, InjectPayload*>;

    PayloadMap callFixupMap_;
    PayloadMap callOtherFixupMap_;
    std::vector<InjectPayload*> callOtherOverride_;
    PayloadMap callMechFixupMap_;
    PayloadMap exePcodeMap_;
    std::vector<InjectPayloadSleigh*> programPayload_;

    void setupOverrides(std::vector<InjectPayloadSleigh*>& userPayloads);

    PayloadMap clonePayloadMap(const PayloadMap& src) const;
};

} // namespace ghidra
