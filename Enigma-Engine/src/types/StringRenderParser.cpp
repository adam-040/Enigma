/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file StringRenderParser.cpp
#include "ghidra/StringRenderParser.h"
#include "ghidra/CharsetInfoManager.h"
#include "ghidra/StringUtilities.h"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <sstream>
#include <stdexcept>

namespace ghidra {

namespace {
const std::string HEX_DIGITS = "0123456789ABCDEFabcdef";

std::string charToString(char c) {
    std::string s;
    s += c;
    return s;
}
}

// ---- StringParseException ----

StringParseException::StringParseException(int pos, const std::string& expected, char got)
    : std::runtime_error("Error parsing string representation at position " +
                         std::to_string(pos) + ". Expected one of " + expected +
                         " but got " + charToString(got)) {}

StringParseException::StringParseException(int pos)
    : std::runtime_error("Unexpected end of string representation at position " +
                         std::to_string(pos) + ".") {}

// ---- StringRenderParser ----

StringRenderParser::StringRenderParser(char quoteChar, Endian endian,
                                       const std::string& charsetName, bool includeBOM)
    : quoteChar_(quoteChar), endian_(endian),
      charsetName_(charsetName), includeBOM_(includeBOM) {
    reset();
}

void StringRenderParser::reset() {
    pos_ = 0;
    state_ = State::INIT;
    val_ = 0;
}

bool StringRenderParser::isHexDigit(char c) {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
}

int StringRenderParser::hexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return 0;
}

bool StringRenderParser::stateAccepts(State s, char c) const {
    switch (s) {
        case State::INIT:
            return c == 'u' || c == 'U' || c == quoteChar_ || c == '\'' || isHexDigit(c);
        case State::PREFIX:
            return c == '8' || c == quoteChar_ || c == '\'' || isHexDigit(c);
        case State::UNIT:
            return c == quoteChar_ || c == '\'' || isHexDigit(c);
        case State::STR:
            return true;
        case State::BYTE:
            return isHexDigit(c);
        case State::BYTE_SUFFIX:
            return c == 'h';
        case State::COMMA:
            return c == ',';
        case State::ESCAPE:
            return c == '0' || c == 'a' || c == 'b' || c == 't' || c == 'n' ||
                   c == 'v' || c == 'f' || c == 'r' || c == '\\' || c == '"' ||
                   c == '\'' || c == 'x' || c == 'u' || c == 'U';
        case State::CODE_POINT:
            return isHexDigit(c);
    }
    return false;
}

bool StringRenderParser::stateIsFinal(State s) const {
    switch (s) {
        case State::INIT:       return true;
        case State::PREFIX:     return false;
        case State::UNIT:       return true;
        case State::STR:        return false;
        case State::BYTE:       return false;
        case State::BYTE_SUFFIX: return false;
        case State::COMMA:      return true;
        case State::ESCAPE:     return false;
        case State::CODE_POINT: return false;
    }
    return false;
}

void StringRenderParser::initCharset(std::vector<uint8_t>& out,
                                      const std::string& reprCharsetName) {
    std::string csName = charsetName_.empty() ? reprCharsetName : charsetName_;
    int charSize = CharsetInfoManager::getInstance().getCharsetCharSize(csName);
    if (CharsetInfoManager::isBOMCharset(csName)) {
        csName += (endian_ == Endian::BIG) ? "BE" : "LE";
    }
    if (includeBOM_) {
        if (charSize == 2) {
            uint16_t bom = static_cast<uint16_t>(StringUtilities::UNICODE_BE_BYTE_ORDER_MARK);
            if (endian_ == Endian::LITTLE) {
                out.push_back(static_cast<uint8_t>(bom & 0xFF));
                out.push_back(static_cast<uint8_t>((bom >> 8) & 0xFF));
            } else {
                out.push_back(static_cast<uint8_t>((bom >> 8) & 0xFF));
                out.push_back(static_cast<uint8_t>(bom & 0xFF));
            }
        } else if (charSize == 4) {
            uint32_t bom = static_cast<uint32_t>(StringUtilities::UNICODE_BE_BYTE_ORDER_MARK);
            if (endian_ == Endian::LITTLE) {
                out.push_back(static_cast<uint8_t>(bom & 0xFF));
                out.push_back(static_cast<uint8_t>((bom >> 8) & 0xFF));
                out.push_back(static_cast<uint8_t>((bom >> 16) & 0xFF));
                out.push_back(static_cast<uint8_t>((bom >> 24) & 0xFF));
            } else {
                out.push_back(static_cast<uint8_t>((bom >> 24) & 0xFF));
                out.push_back(static_cast<uint8_t>((bom >> 16) & 0xFF));
                out.push_back(static_cast<uint8_t>((bom >> 8) & 0xFF));
                out.push_back(static_cast<uint8_t>(bom & 0xFF));
            }
        }
    }
}

StringRenderParser::State StringRenderParser::parseCharInit(std::vector<uint8_t>& out, char c) {
    if (c == 'u') {
        return State::PREFIX;
    }
    if (c == 'U') {
        initCharset(out, CharsetInfoManager::UTF32);
        return State::UNIT;
    }
    initCharset(out, CharsetInfoManager::USASCII);
    return parseCharUnit(out, c);
}

StringRenderParser::State StringRenderParser::parseCharPrefix(std::vector<uint8_t>& out, char c) {
    if (c == '8') {
        initCharset(out, CharsetInfoManager::UTF8);
        return State::UNIT;
    }
    initCharset(out, CharsetInfoManager::UTF16);
    return parseCharUnit(out, c);
}

StringRenderParser::State StringRenderParser::parseCharUnit(std::vector<uint8_t>& out, char c) {
    if (isHexDigit(c)) {
        val_ = hexVal(c);
        return State::BYTE;
    }
    if (c == quoteChar_ || c == '\'') {
        return State::STR;
    }
    return state_;
}

StringRenderParser::State StringRenderParser::parseCharStr(std::vector<uint8_t>& out, char c) {
    if (c == quoteChar_ || c == '\'') {
        return State::COMMA;
    }
    if (c == '\\') {
        return State::ESCAPE;
    }
    encodeChar(out, c);
    return State::STR;
}

StringRenderParser::State StringRenderParser::parseCharByte(std::vector<uint8_t>& out, char c) {
    val_ = (val_ << 4) + hexVal(c);
    return State::BYTE_SUFFIX;
}

StringRenderParser::State StringRenderParser::parseCharByteSuffix(std::vector<uint8_t>& out,
                                                                    char c) {
    if (c == 'h') {
        out.push_back(static_cast<uint8_t>(val_));
        val_ = 0;
        return State::COMMA;
    }
    return state_;
}

StringRenderParser::State StringRenderParser::parseCharComma(std::vector<uint8_t>& out, char c) {
    if (c == ',') {
        return State::UNIT;
    }
    return state_;
}

StringRenderParser::State StringRenderParser::parseCharEscape(std::vector<uint8_t>& out, char c) {
    switch (c) {
        case '0': encodeChar(out, '\0'); return State::STR;
        case 'a': encodeChar(out, static_cast<char>(7)); return State::STR;
        case 'b': encodeChar(out, '\b'); return State::STR;
        case 't': encodeChar(out, '\t'); return State::STR;
        case 'n': encodeChar(out, '\n'); return State::STR;
        case 'v': encodeChar(out, static_cast<char>(11)); return State::STR;
        case 'f': encodeChar(out, '\f'); return State::STR;
        case 'r': encodeChar(out, '\r'); return State::STR;
        case '\\': encodeChar(out, '\\'); return State::STR;
        case '"': encodeChar(out, '"'); return State::STR;
        case '\'': encodeChar(out, '\''); return State::STR;
        case 'x': codeDigits_ = 2; return State::CODE_POINT;
        case 'u': codeDigits_ = 4; return State::CODE_POINT;
        case 'U': codeDigits_ = 8; return State::CODE_POINT;
        default: return state_;
    }
}

StringRenderParser::State StringRenderParser::parseCharCodePoint(std::vector<uint8_t>& out,
                                                                   char c) {
    val_ = (val_ << 4) + hexVal(c);
    if (--codeDigits_ == 0) {
        encodeCodePoint(out, val_);
        val_ = 0;
        return State::STR;
    }
    return State::CODE_POINT;
}

StringRenderParser::State StringRenderParser::parseChar(std::vector<uint8_t>& out, char c) {
    switch (state_) {
        case State::INIT:        return parseCharInit(out, c);
        case State::PREFIX:      return parseCharPrefix(out, c);
        case State::UNIT:        return parseCharUnit(out, c);
        case State::STR:         return parseCharStr(out, c);
        case State::BYTE:        return parseCharByte(out, c);
        case State::BYTE_SUFFIX: return parseCharByteSuffix(out, c);
        case State::COMMA:       return parseCharComma(out, c);
        case State::ESCAPE:      return parseCharEscape(out, c);
        case State::CODE_POINT:  return parseCharCodePoint(out, c);
    }
    return state_;
}

void StringRenderParser::encodeCodePoint(std::vector<uint8_t>& out, int cp) {
    if (cp < 0x10000) {
        encodeChar(out, static_cast<char>(cp));
    } else {
        int hi = 0xD800 + ((cp - 0x10000) >> 10);
        int lo = 0xDC00 + ((cp - 0x10000) & 0x3FF);
        encodeChar(out, static_cast<char>(hi));
        encodeChar(out, static_cast<char>(lo));
    }
}

void StringRenderParser::encodeChar(std::vector<uint8_t>& out, char c) {
    unsigned char uc = static_cast<unsigned char>(c);
    out.push_back(uc);
}

std::vector<uint8_t> StringRenderParser::parse(const std::string& input) {
    reset();
    size_t bufSize = input.size() * 2;
    bool done = false;
    std::vector<uint8_t> result;

    while (!done) {
        result.clear();
        result.reserve(bufSize);
        reset();
        pos_ = 0;

        bool error = false;
        try {
            for (size_t i = 0; i < input.size(); ++i) {
                char c = input[i];
                if (!stateAccepts(state_, c)) {
                    std::string expected;
                    throw StringParseException(pos_, expected, c);
                }
                state_ = parseChar(result, c);
                pos_++;
            }
            if (!stateIsFinal(state_)) {
                throw StringParseException(pos_);
            }
        } catch (const StringParseException&) {
            throw;
        } catch (const std::bad_alloc&) {
            bufSize <<= 1;
            error = true;
        }
        if (!error) {
            done = true;
        }
    }

    return result;
}

} // namespace ghidra
