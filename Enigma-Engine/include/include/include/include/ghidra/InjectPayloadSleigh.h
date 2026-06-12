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

namespace ghidra {

class ConstructTpl;

class InjectPayloadSleigh : public InjectPayload {
public:
    std::string name;
    int type;
    std::string source;

    InjectPayloadSleigh(const std::string& nm, int tp, const std::string& src)
        : name(nm), type(tp), source(src) {}

    std::string getName() const override { return name; }
    int getType() const override { return type; }
    std::string getSource() const override { return source; }

    int getParamShift() const override { return 0; }
    std::vector<InjectParameter> getInput() const override { return {}; }
    std::vector<InjectParameter> getOutput() const override { return {}; }
    bool isErrorPlaceholder() const override { return false; }

    void inject(InjectContext* context, PcodeEmit* emit) override {}
    std::vector<PcodeOp*> getPcode(Program* program, InjectContext* con) override { return {}; }
    bool isFallThru() const override { return true; }
    bool isIncidentalCopy() const override { return false; }
    void encode(Encoder& encoder) override {}
    void restoreXml(XmlPullParser* parser, SleighLanguage* language) override {}
    bool isEquivalent(const InjectPayload* obj) const override { return false; }

    std::string releaseParseString() { auto s = parseString_; parseString_ = {}; return s; }
    void setTemplate(ConstructTpl* tpl) { tpl_ = tpl; }
    ConstructTpl* getTemplate() const { return tpl_; }

protected:
    std::string parseString_;
    ConstructTpl* tpl_ = nullptr;
};

} // namespace ghidra
