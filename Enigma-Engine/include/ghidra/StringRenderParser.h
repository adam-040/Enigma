/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file StringRenderParser.h
/// \brief Parses a formatted string representation back to bytes.
/// Translated from: ghidra.program.model.data.StringRenderParser
#pragma once

#include "Endian.h"
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace ghidra {

class StringParseException : public std::runtime_error {
public:
    StringParseException(int pos, const std::string& expected, char got);
    explicit StringParseException(int pos);
};

class StringRenderParser {
public:
    StringRenderParser(char quoteChar, Endian endian, const std::string& charsetName,
                       bool includeBOM);

    void reset();
    std::vector<uint8_t> parse(const std::string& input);

private:
    enum class State {
        INIT,
        PREFIX,
        UNIT,
        STR,
        BYTE,
        BYTE_SUFFIX,
        COMMA,
        ESCAPE,
        CODE_POINT
    };

    static bool isHexDigit(char c);
    static int hexVal(char c);
    bool stateAccepts(State s, char c) const;
    bool stateIsFinal(State s) const;

    void initCharset(std::vector<uint8_t>& out, const std::string& reprCharsetName);

    State parseCharInit(std::vector<uint8_t>& out, char c);
    State parseCharPrefix(std::vector<uint8_t>& out, char c);
    State parseCharUnit(std::vector<uint8_t>& out, char c);
    State parseCharStr(std::vector<uint8_t>& out, char c);
    State parseCharByte(std::vector<uint8_t>& out, char c);
    State parseCharByteSuffix(std::vector<uint8_t>& out, char c);
    State parseCharComma(std::vector<uint8_t>& out, char c);
    State parseCharEscape(std::vector<uint8_t>& out, char c);
    State parseCharCodePoint(std::vector<uint8_t>& out, char c);

    State parseChar(std::vector<uint8_t>& out, char c);

    void encodeCodePoint(std::vector<uint8_t>& out, int cp);
    void encodeChar(std::vector<uint8_t>& out, char c);

    char quoteChar_;
    Endian endian_;
    std::string charsetName_;
    bool includeBOM_;

    State state_ = State::INIT;
    int val_ = 0;
    int codeDigits_ = 0;
    int pos_ = 0;
};

} // namespace ghidra
