/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * ...
 */
/// \file StringUtilities.h
/// \brief Static string manipulation utilities
/// Translated from: ghidra.util.StringUtilities
#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace ghidra {

class StringUtilities {
public:
    static constexpr int UNICODE_REPLACEMENT = 0xFFFD;
    static constexpr int UNICODE_BE_BYTE_ORDER_MARK = 0xFEFF;
    static constexpr int UNICODE_LE16_BYTE_ORDER_MARK = 0xFFFE;
    static constexpr int UNICODE_LE32_BYTE_ORDER_MARK = 0xFFFE0000;
    static constexpr int DEFAULT_TAB_SIZE = 8;
    static constexpr const char* ELLIPSES = "...";

    StringUtilities() = delete;

    static bool isControlCharacterOrBackslash(char c);
    static bool isDisplayable(int c);
    static std::string characterToString(char c);

    static std::string toQuotedString(const std::vector<uint8_t>& bytes);
    static std::string toQuotedString(const std::vector<uint8_t>& bytes, int charSize);

    static bool startsWithIgnoreCase(const std::string& str, const std::string& prefix);
    static bool endsWithIgnoreCase(const std::string& str, const std::string& postfix);
    static int countOccurrences(const std::string& str, char occur);
    static bool equals(const std::string& s1, const std::string& s2, bool caseSensitive);
    static bool endsWithWhiteSpace(const std::string& str);
    static bool containsAll(const std::string& toSearch, const std::vector<std::string>& searches);
    static bool containsAllIgnoreCase(const std::string& toSearch, const std::vector<std::string>& searches);
    static bool containsAnyIgnoreCase(const std::string& toSearch, const std::vector<std::string>& searches);

    static int indexOfWord(const std::string& text, const std::string& searchWord);
    static bool isWholeWord(const std::string& text, int startIndex, int length);

    static std::string convertTabsToSpaces(const std::string& str, int tabSize = DEFAULT_TAB_SIZE);
    static std::vector<std::string> toLines(const std::string& str, bool preserveTokens = true);
    static std::string pad(const std::string& source, char filler, int length);
    static std::string trim(const std::string& original, int max);
    static std::string trimMiddle(const std::string& s, int max);
    static std::string trimTrailingNulls(const std::string& s);
    static std::string indentLines(const std::string& s, const std::string& indent);
    static std::string findWord(const std::string& s, int index);
    static std::string getLastWord(const std::string& s, const std::string& separator);
    static bool isValidCLanguageChar(char c);
    static bool isAsciiChar(char c);

    static std::string convertEscapeSequences(const std::string& str);
    static std::string convertControlCharsToEscapeSequences(const std::string& str);
    static std::string mergeStrings(const std::string& string1, const std::string& string2);
    static std::string whitespaceToUnderscores(const std::string& s);
    static std::string toFixedSize(const std::string& s, char padChar, int size);

    class LineWrapper {
    public:
        LineWrapper(int width);
        LineWrapper& append(const std::string& cs);
        std::string finish();
    private:
        int width_;
        std::string result_;
        int len_ = 0;
        void appendWord(const std::string& word);
        void appendSpace(const std::string& space);
        void appendLinesep();
    };

    static std::string wrapToWidth(const std::string& str, int width);
};

} // namespace ghidra
