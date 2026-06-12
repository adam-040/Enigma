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

#include <ghidra/PcodeOp.h>
#include <ghidra/Encoder.h>
#include <string>
#include <vector>

namespace ghidra {

class InjectContext;
class PcodeEmit;
class Program;
class SleighLanguage;
class XmlPullParser;

class InjectPayload {
public:
    static constexpr int CALLFIXUP_TYPE = 1;
    static constexpr int CALLOTHERFIXUP_TYPE = 2;
    static constexpr int CALLMECHANISM_TYPE = 3;
    static constexpr int EXECUTABLEPCODE_TYPE = 4;

    struct InjectParameter {
        std::string name;
        int index = 0;
        int size = 0;

        InjectParameter() = default;
        InjectParameter(const std::string& nm, int sz) : name(nm), index(0), size(sz) {}

        std::string getName() const { return name; }
        int getIndex() const { return index; }
        int getSize() const { return size; }
        void setIndex(int i) { index = i; }

        bool isEquivalent(const InjectParameter& other) const {
            return name == other.name && index == other.index && size == other.size;
        }
    };

    virtual ~InjectPayload() = default;
    virtual std::string getName() const = 0;
    virtual int getType() const = 0;
    virtual std::string getSource() const = 0;
    virtual int getParamShift() const = 0;
    virtual std::vector<InjectParameter> getInput() const = 0;
    virtual std::vector<InjectParameter> getOutput() const = 0;
    virtual bool isErrorPlaceholder() const = 0;
    virtual void inject(InjectContext* context, PcodeEmit* emit) = 0;
    virtual std::vector<PcodeOp*> getPcode(Program* program, InjectContext* con) = 0;
    virtual bool isFallThru() const = 0;
    virtual bool isIncidentalCopy() const = 0;
    virtual void encode(Encoder& encoder) = 0;
    virtual void restoreXml(XmlPullParser* parser, SleighLanguage* language) = 0;
    virtual bool isEquivalent(const InjectPayload* obj) const = 0;
};

} // namespace ghidra
