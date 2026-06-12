/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file StringRenderBuilder.cpp
#include "ghidra/StringRenderBuilder.h"
#include "ghidra/StringUtilities.h"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <stdexcept>
#include <vector>

namespace ghidra {

namespace {

bool isISOControl(int cp) {
    return (cp >= 0x00 && cp <= 0x1f) || (cp >= 0x7f && cp <= 0x9f);
}

bool isDefinedCodepoint(int cp) {
    if (cp < 0) return false;
    if (cp >= 0xD800 && cp <= 0xDFFF) return false;
    if (cp >= 0xFDD0 && cp <= 0xFDEF) return false;
    if ((cp & 0xFFFE) == 0xFFFE && cp <= 0x10FFFF) return false;
    return cp <= 0x10FFFF;
}

bool isBMP(int cp) {
    return cp <= 0xFFFF;
}

int charCount(int cp) {
    return cp > 0xFFFF ? 2 : 1;
}

bool charsetIsLittleEndian(const std::string& name) {
    std::string upper = name;
    std::transform(upper.begin(), upper.end(), upper.begin(),
        [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return upper.find("LE") != std::string::npos;
}

}

StringRenderBuilder::StringRenderBuilder(const std::string& charsetName, int charSize)
    : StringRenderBuilder(charsetName, charSize, DOUBLE_QUOTE) {}

StringRenderBuilder::StringRenderBuilder(const std::string& charsetName, int charSize,
                                         char quoteChar)
    : charsetName_(charsetName), charSize_(charSize), quoteChar_(quoteChar) {
    std::string upper;
    upper.reserve(charsetName.size());
    for (char c : charsetName) {
        upper.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    }
    utfCharset_ = upper.find("UTF") == 0;
}

void StringRenderBuilder::addEscapedCodePoint(int codePoint) {
    ensureTextMode();
    char escapeChar = (codePoint < 0x80) ? 'x' : isBMP(codePoint) ? 'u' : 'U';
    int cpDigits = (codePoint < 0x80) ? 2 : isBMP(codePoint) ? 4 : 8;
    char fmt[16];
    snprintf(fmt, sizeof(fmt), "%%0%dX", cpDigits);
    char hex[16];
    snprintf(hex, sizeof(hex), fmt, codePoint);
    sb_ += '\\';
    sb_ += escapeChar;
    sb_ += hex;
}

void StringRenderBuilder::decodeBytesUsingCharset(const std::vector<uint8_t>& bytes,
                                                   RenderUnicodeEnum renderSetting,
                                                   bool trimTrailingNulls) {
    if (bytes.empty()) return;

    bool le = charsetIsLittleEndian(charsetName_);
    std::vector<int> codepoints;
    size_t offset = 0;
    while (offset < bytes.size()) {
        size_t start = offset;
        int cp = -1;
        if (charSize_ == 1) {
            cp = decodeUTF8(bytes, offset);
        } else if (charSize_ == 2) {
            cp = decodeUTF16(bytes, offset, le);
        } else if (charSize_ == 4) {
            cp = decodeUTF32(bytes, offset, le);
        }
        if (cp < 0) {
            if (offset == start) {
                offset = start + 1;
            }
            for (size_t i = start; i < offset; ++i) {
                addByteSeq(bytes, i, 1);
            }
        } else {
            codepoints.push_back(cp);
        }
    }

    if (trimTrailingNulls) {
        while (!codepoints.empty() && codepoints.back() == 0) {
            codepoints.pop_back();
        }
    }

    if (!codepoints.empty()) {
        renderChars(codepoints, renderSetting);
    }
}

void StringRenderBuilder::addString(const std::string& str) {
    ensureTextMode();
    sb_ += str;
}

void StringRenderBuilder::addCodePointChar(int codePoint) {
    ensureTextMode();
    if (codePoint == static_cast<int>(quoteChar_)) {
        sb_ += '\\';
    }
    if (isBMP(codePoint)) {
        sb_ += static_cast<char>(codePoint);
    } else {
        int hi = 0xD800 + ((codePoint - 0x10000) >> 10);
        int lo = 0xDC00 + ((codePoint - 0x10000) & 0x3FF);
        sb_ += static_cast<char>(hi);
        sb_ += static_cast<char>(lo);
    }
}

void StringRenderBuilder::addByteSeq(uint8_t byteValue) {
    ensureByteMode();
    char buf[8];
    snprintf(buf, sizeof(buf), "%02hhXh", byteValue);
    sb_ += buf;
}

void StringRenderBuilder::addByteSeq(const std::vector<uint8_t>& bytes,
                                      size_t start, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        addByteSeq(bytes[start + i]);
    }
}

void StringRenderBuilder::addByteSeq(int codePoint) {
    std::vector<uint8_t> encoded;
    bool le = charsetIsLittleEndian(charsetName_);
    encodeCodePointToBytes(codePoint, charSize_, le, encoded);
    for (uint8_t b : encoded) {
        addByteSeq(b);
    }
}

std::string StringRenderBuilder::codePointToEscapeSequence(int cp) {
    switch (cp) {
        case 0:   return "\\0";
        case 7:   return "\\a";
        case '\b': return "\\b";
        case '\t': return "\\t";
        case '\n': return "\\n";
        case 11:  return "\\v";
        case '\f': return "\\f";
        case '\r': return "\\r";
        case '\\': return "\\\\";
        default: {
            char buf[16];
            snprintf(buf, sizeof(buf), "\\x%02X", cp);
            return buf;
        }
    }
}

void StringRenderBuilder::ensureTextMode() {
    if (sb_.empty()) {
        sb_ += quoteChar_;
    } else if (byteMode_) {
        sb_ += ',';
        sb_ += quoteChar_;
    }
    byteMode_ = false;
}

void StringRenderBuilder::ensureByteMode() {
    if (!byteMode_) {
        sb_ += quoteChar_;
    }
    if (!sb_.empty()) {
        sb_ += ',';
    }
    byteMode_ = true;
}

void StringRenderBuilder::renderChars(const std::vector<int>& codepoints,
                                       RenderUnicodeEnum renderSetting) {
    for (size_t i = 0; i < codepoints.size(); ++i) {
        int cp = codepoints[i];

        if (cp == 0) {
            if (byteMode_) {
                addByteSeq(cp);
            } else {
                addString("\\0");
            }
        } else if (isISOControl(cp)) {
            std::string esc = codePointToEscapeSequence(cp);
            if (esc.size() == 2 && esc[0] == '\\' && esc[1] != 'x') {
                addString(esc);
            } else {
                addByteSeq(cp);
            }
        } else if (!isDefinedCodepoint(cp)) {
            addByteSeq(cp);
        } else if (StringUtilities::isDisplayable(cp)) {
            addCodePointChar(cp);
        } else if (cp == StringUtilities::UNICODE_BE_BYTE_ORDER_MARK) {
            addEscapedCodePoint(cp);
        } else {
            switch (renderSetting) {
                default:
                case RenderUnicodeEnum::ALL:
                    addCodePointChar(cp);
                    break;
                case RenderUnicodeEnum::BYTE_SEQ:
                    addByteSeq(cp);
                    break;
                case RenderUnicodeEnum::ESC_SEQ:
                    addEscapedCodePoint(cp);
                    break;
            }
        }
    }
}

int StringRenderBuilder::decodeUTF8(const std::vector<uint8_t>& bytes, size_t& offset) {
    if (offset >= bytes.size()) return -1;
    uint8_t b0 = bytes[offset];
    if (b0 < 0x80) {
        offset++;
        return b0;
    }
    if (b0 < 0xC0) {
        offset++;
        return -1;
    }
    if (b0 < 0xE0) {
        if (offset + 1 >= bytes.size()) return -1;
        uint8_t b1 = bytes[offset + 1];
        if ((b1 & 0xC0) != 0x80) { offset += 2; return -1; }
        offset += 2;
        return ((b0 & 0x1F) << 6) | (b1 & 0x3F);
    }
    if (b0 < 0xF0) {
        if (offset + 2 >= bytes.size()) return -1;
        uint8_t b1 = bytes[offset + 1];
        uint8_t b2 = bytes[offset + 2];
        if ((b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80) { offset += 3; return -1; }
        offset += 3;
        return ((b0 & 0x0F) << 12) | ((b1 & 0x3F) << 6) | (b2 & 0x3F);
    }
    if (b0 < 0xF8) {
        if (offset + 3 >= bytes.size()) return -1;
        uint8_t b1 = bytes[offset + 1];
        uint8_t b2 = bytes[offset + 2];
        uint8_t b3 = bytes[offset + 3];
        if ((b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80 || (b3 & 0xC0) != 0x80) { offset += 4; return -1; }
        offset += 4;
        return ((b0 & 0x07) << 18) | ((b1 & 0x3F) << 12) | ((b2 & 0x3F) << 6) | (b3 & 0x3F);
    }
    offset++;
    return -1;
}

int StringRenderBuilder::decodeUTF16(const std::vector<uint8_t>& bytes, size_t& offset,
                                      bool littleEndian) {
    if (offset + 2 > bytes.size()) return -1;
    uint16_t unit;
    if (littleEndian) {
        unit = static_cast<uint16_t>(bytes[offset]) |
               (static_cast<uint16_t>(bytes[offset + 1]) << 8);
    } else {
        unit = (static_cast<uint16_t>(bytes[offset]) << 8) |
               static_cast<uint16_t>(bytes[offset + 1]);
    }
    offset += 2;
    if (unit >= 0xD800 && unit <= 0xDBFF) {
        if (offset + 2 > bytes.size()) return -1;
        uint16_t lo;
        if (littleEndian) {
            lo = static_cast<uint16_t>(bytes[offset]) |
                 (static_cast<uint16_t>(bytes[offset + 1]) << 8);
        } else {
            lo = (static_cast<uint16_t>(bytes[offset]) << 8) |
                  static_cast<uint16_t>(bytes[offset + 1]);
        }
        offset += 2;
        if (lo < 0xDC00 || lo > 0xDFFF) return -1;
        return 0x10000 + ((unit - 0xD800) << 10) + (lo - 0xDC00);
    }
    if (unit >= 0xDC00 && unit <= 0xDFFF) return -1;
    return unit;
}

int StringRenderBuilder::decodeUTF32(const std::vector<uint8_t>& bytes, size_t& offset,
                                      bool littleEndian) {
    if (offset + 4 > bytes.size()) return -1;
    uint32_t cp;
    if (littleEndian) {
        cp = static_cast<uint32_t>(bytes[offset]) |
             (static_cast<uint32_t>(bytes[offset + 1]) << 8) |
             (static_cast<uint32_t>(bytes[offset + 2]) << 16) |
             (static_cast<uint32_t>(bytes[offset + 3]) << 24);
    } else {
        cp = (static_cast<uint32_t>(bytes[offset]) << 24) |
             (static_cast<uint32_t>(bytes[offset + 1]) << 16) |
             (static_cast<uint32_t>(bytes[offset + 2]) << 8) |
              static_cast<uint32_t>(bytes[offset + 3]);
    }
    offset += 4;
    if (cp > 0x10FFFF) return -1;
    return static_cast<int>(cp);
}

int StringRenderBuilder::encodeUTF8(int codePoint, std::vector<uint8_t>& out) {
    if (codePoint < 0x80) {
        out.push_back(static_cast<uint8_t>(codePoint));
        return 1;
    }
    if (codePoint < 0x800) {
        out.push_back(static_cast<uint8_t>(0xC0 | (codePoint >> 6)));
        out.push_back(static_cast<uint8_t>(0x80 | (codePoint & 0x3F)));
        return 2;
    }
    if (codePoint < 0x10000) {
        out.push_back(static_cast<uint8_t>(0xE0 | (codePoint >> 12)));
        out.push_back(static_cast<uint8_t>(0x80 | ((codePoint >> 6) & 0x3F)));
        out.push_back(static_cast<uint8_t>(0x80 | (codePoint & 0x3F)));
        return 3;
    }
    if (codePoint <= 0x10FFFF) {
        out.push_back(static_cast<uint8_t>(0xF0 | (codePoint >> 18)));
        out.push_back(static_cast<uint8_t>(0x80 | ((codePoint >> 12) & 0x3F)));
        out.push_back(static_cast<uint8_t>(0x80 | ((codePoint >> 6) & 0x3F)));
        out.push_back(static_cast<uint8_t>(0x80 | (codePoint & 0x3F)));
        return 4;
    }
    return 0;
}

int StringRenderBuilder::encodeUTF16(int codePoint, std::vector<uint8_t>& out, bool littleEndian) {
    (void)littleEndian;
    if (codePoint < 0x10000) {
        if (littleEndian) {
            out.push_back(static_cast<uint8_t>(codePoint & 0xFF));
            out.push_back(static_cast<uint8_t>((codePoint >> 8) & 0xFF));
        } else {
            out.push_back(static_cast<uint8_t>((codePoint >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>(codePoint & 0xFF));
        }
        return 2;
    }
    if (codePoint <= 0x10FFFF) {
        int hi = 0xD800 + ((codePoint - 0x10000) >> 10);
        int lo = 0xDC00 + ((codePoint - 0x10000) & 0x3FF);
        if (littleEndian) {
            out.push_back(static_cast<uint8_t>(hi & 0xFF));
            out.push_back(static_cast<uint8_t>((hi >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>(lo & 0xFF));
            out.push_back(static_cast<uint8_t>((lo >> 8) & 0xFF));
        } else {
            out.push_back(static_cast<uint8_t>((hi >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>(hi & 0xFF));
            out.push_back(static_cast<uint8_t>((lo >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>(lo & 0xFF));
        }
        return 4;
    }
    return 0;
}

int StringRenderBuilder::encodeUTF32(int codePoint, std::vector<uint8_t>& out, bool littleEndian) {
    if (codePoint <= 0x10FFFF) {
        if (littleEndian) {
            out.push_back(static_cast<uint8_t>(codePoint & 0xFF));
            out.push_back(static_cast<uint8_t>((codePoint >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>((codePoint >> 16) & 0xFF));
            out.push_back(static_cast<uint8_t>((codePoint >> 24) & 0xFF));
        } else {
            out.push_back(static_cast<uint8_t>((codePoint >> 24) & 0xFF));
            out.push_back(static_cast<uint8_t>((codePoint >> 16) & 0xFF));
            out.push_back(static_cast<uint8_t>((codePoint >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>(codePoint & 0xFF));
        }
        return 4;
    }
    return 0;
}

void StringRenderBuilder::encodeCodePointToBytes(int codePoint, int charSize,
                                                   bool littleEndian,
                                                   std::vector<uint8_t>& out) {
    if (codePoint < 0) return;
    if (charSize == 1) {
        encodeUTF8(codePoint, out);
    } else if (charSize == 2) {
        encodeUTF16(codePoint, out, littleEndian);
    } else if (charSize == 4) {
        encodeUTF32(codePoint, out, littleEndian);
    }
}

std::string StringRenderBuilder::build() const {
    std::string s = sb_.empty() ? std::string(1, quoteChar_) + quoteChar_ : toString();
    std::string prefix;
    if (utfCharset_ && !s.empty() && s[0] == quoteChar_) {
        switch (charSize_) {
            case 1: prefix = "u8"; break;
            case 2: prefix = "u"; break;
            case 4: prefix = "U"; break;
            default: break;
        }
    }
    return prefix + s;
}

std::string StringRenderBuilder::toString() const {
    std::string str = sb_;
    if (!byteMode_) {
        str += quoteChar_;
    }
    return str;
}

} // namespace ghidra
