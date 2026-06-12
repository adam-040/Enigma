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

#include <ghidra/Register.h>
#include <ghidra/Address.h>
#include <ghidra/Encoder.h>
#include <string>
#include <vector>

namespace ghidra {

class CompilerSpec;
class XmlPullParser;

class ContextSetting {
public:
    ContextSetting(Register* reg, uint64_t value, const Address& startAddr, const Address& endAddr);

    Register* getRegister() const { return register_; }
    uint64_t getValue() const { return value_; }
    const Address& getStartAddress() const { return startAddr_; }
    const Address& getEndAddress() const { return endAddr_; }

    void encode(Encoder& encoder);
    bool isEquivalent(const ContextSetting& obj) const;

    static void parseContextSet(std::vector<ContextSetting>& resList,
                                XmlPullParser* parser, CompilerSpec* cspec);
    static void parseContextData(std::vector<ContextSetting>& resList,
                                 XmlPullParser* parser, CompilerSpec* cspec);
    static void encodeContextData(Encoder& encoder,
                                  const std::vector<ContextSetting>& ctxList);

private:
    Register* register_ = nullptr;
    uint64_t value_ = 0;
    Address startAddr_;
    Address endAddr_;

    static uint64_t parseBigInteger(const std::string& valStr, uint64_t defaultValue);
};

} // namespace ghidra
