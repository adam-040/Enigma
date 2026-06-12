/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file StringRenderBuilder.h
/// \brief Builds a formatted string representation of string data.
/// Translated from: ghidra.program.model.data.StringRenderBuilder
#pragma once

#include "RenderUnicodeSettingsDefinition.h"
#include <cstdint>
#include <string>
#include <vector>

namespace ghidra {

class StringRenderBuilder {
public:
    static constexpr char DOUBLE_QUOTE = '"';
    static constexpr char SINGLE_QUOTE = '\'';

    StringRenderBuilder(const std::string& charsetName, int charSize);
    StringRenderBuilder(const std::string& charsetName, int charSize, char quoteChar);

    void addEscapedCodePoint(int codePoint);
    void decodeBytesUsingCharset(const std::vector<uint8_t>& bytes,
                                 RenderUnicodeEnum renderSetting,
                                 bool trimTrailingNulls);
    std::string build() const;
    std::string toString() const;

private:
    void addString(const std::string& str);
    void addCodePointChar(int codePoint);
    void addByteSeq(uint8_t byteValue);
    void addByteSeq(const std::vector<uint8_t>& bytes, size_t start, size_t count);
    void addByteSeq(int codePoint);
    static std::string codePointToEscapeSequence(int cp);
    void ensureTextMode();
    void ensureByteMode();
    void renderChars(const std::vector<int>& codepoints, RenderUnicodeEnum renderSetting);

    static int decodeUTF8(const std::vector<uint8_t>& bytes, size_t& offset);
    static int decodeUTF16(const std::vector<uint8_t>& bytes, size_t& offset, bool littleEndian);
    static int decodeUTF32(const std::vector<uint8_t>& bytes, size_t& offset, bool littleEndian);
    static int encodeUTF8(int codepoint, std::vector<uint8_t>& out);
    static int encodeUTF16(int codepoint, std::vector<uint8_t>& out, bool littleEndian);
    static int encodeUTF32(int codepoint, std::vector<uint8_t>& out, bool littleEndian);
    static void encodeCodePointToBytes(int codePoint, int charSize,
                                       bool littleEndian, std::vector<uint8_t>& out);

    std::string sb_;
    std::string charsetName_;
    int charSize_;
    bool utfCharset_;
    char quoteChar_;
    bool byteMode_ = true;
};

} // namespace ghidra
