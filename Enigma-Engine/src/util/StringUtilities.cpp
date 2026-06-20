/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 */
/// \file StringUtilities.cpp
/// \brief Static string manipulation utilities
#include <ghidra/StringUtilities.h>
#include <algorithm>
#include <cctype>
#include <sstream>
#include <cstring>
#include <cwchar>

namespace ghidra {

// ---- Character Classification ----

bool StringUtilities::isControlCharacterOrBackslash(char c) {
    return (c >= 0x00 && c <= 0x1f) || c == '\\';
}

bool StringUtilities::isDisplayable(int c) {
    if (c < 0x20) return false;
    if (c > 0x7e) {
        // treat as displayable if it's a valid Unicode char
        return true;
    }
    return true;
}

std::string StringUtilities::characterToString(char c) {
    if (c == '\t') return "\\t";
    if (c == '\n') return "\\n";
    if (c == '\r') return "\\r";
    if (c == '\\') return "\\\\";
    if (c < 0x20) {
        char buf[8];
        snprintf(buf, sizeof(buf), "\\x%02x", static_cast<unsigned char>(c));
        return buf;
    }
    return std::string(1, c);
}

// ---- QuotedString ----

std::string StringUtilities::toQuotedString(const std::vector<uint8_t>& bytes) {
    return toQuotedString(bytes, 1);
}

std::string StringUtilities::toQuotedString(const std::vector<uint8_t>& bytes, int charSize) {
    std::string result;
    result.reserve(bytes.size() * 4 + 2);
    result.push_back('"');
    for (size_t i = 0; i < bytes.size(); i += charSize) {
        uint8_t b = bytes[i];
        if (b == '"') {
            result += "\\\"";
        } else if (b == '\\') {
            result += "\\\\";
        } else if (b == '\n') {
            result += "\\n";
        } else if (b == '\t') {
            result += "\\t";
        } else if (b == '\r') {
            result += "\\r";
        } else if (b >= 0x20 && b < 0x7f) {
            result.push_back(static_cast<char>(b));
        } else {
            char buf[8];
            snprintf(buf, sizeof(buf), "\\x%02x", b);
            result += buf;
        }
    }
    result.push_back('"');
    return result;
}

// ---- Comparison ----

bool StringUtilities::startsWithIgnoreCase(const std::string& str, const std::string& prefix) {
    if (str.size() < prefix.size()) return false;
    return std::equal(prefix.begin(), prefix.end(), str.begin(),
        [](char a, char b) { return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b)); });
}

bool StringUtilities::endsWithIgnoreCase(const std::string& str, const std::string& postfix) {
    if (str.size() < postfix.size()) return false;
    return std::equal(postfix.begin(), postfix.end(), str.end() - postfix.size(),
        [](char a, char b) { return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b)); });
}

int StringUtilities::countOccurrences(const std::string& str, char occur) {
    return static_cast<int>(std::count(str.begin(), str.end(), occur));
}

bool StringUtilities::equals(const std::string& s1, const std::string& s2, bool caseSensitive) {
    if (caseSensitive) return s1 == s2;
    if (s1.size() != s2.size()) return false;
    return std::equal(s1.begin(), s1.end(), s2.begin(),
        [](char a, char b) { return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b)); });
}

bool StringUtilities::endsWithWhiteSpace(const std::string& str) {
    if (str.empty()) return false;
    char c = str.back();
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

bool StringUtilities::containsAll(const std::string& toSearch, const std::vector<std::string>& searches) {
    for (const auto& s : searches) {
        if (toSearch.find(s) == std::string::npos) return false;
    }
    return true;
}

bool StringUtilities::containsAllIgnoreCase(const std::string& toSearch, const std::vector<std::string>& searches) {
    std::string lower = toSearch;
    std::transform(lower.begin(), lower.end(), lower.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    for (const auto& s : searches) {
        std::string sl = s;
        std::transform(sl.begin(), sl.end(), sl.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (lower.find(sl) == std::string::npos) return false;
    }
    return true;
}

bool StringUtilities::containsAnyIgnoreCase(const std::string& toSearch, const std::vector<std::string>& searches) {
    std::string lower = toSearch;
    std::transform(lower.begin(), lower.end(), lower.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    for (const auto& s : searches) {
        std::string sl = s;
        std::transform(sl.begin(), sl.end(), sl.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (lower.find(sl) != std::string::npos) return true;
    }
    return false;
}

// ---- Word Utils ----

int StringUtilities::indexOfWord(const std::string& text, const std::string& searchWord) {
    if (searchWord.empty()) return -1;
    size_t pos = 0;
    while (true) {
        pos = text.find(searchWord, pos);
        if (pos == std::string::npos) return -1;
        if (isWholeWord(text, static_cast<int>(pos), static_cast<int>(searchWord.size()))) {
            return static_cast<int>(pos);
        }
        pos++;
    }
}

bool StringUtilities::isWholeWord(const std::string& text, int startIndex, int length) {
    if (startIndex < 0 || length < 0) return false;
    // Check preceding char
    if (startIndex > 0) {
        char c = text[startIndex - 1];
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_') return false;
    }
    // Check following char
    int end = startIndex + length;
    if (end < static_cast<int>(text.size())) {
        char c = text[end];
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_') return false;
    }
    return true;
}

// ---- Formatting ----

std::string StringUtilities::convertTabsToSpaces(const std::string& str, int tabSize) {
    std::string result;
    result.reserve(str.size() * 2);
    int col = 0;
    for (char c : str) {
        if (c == '\t') {
            int spaces = tabSize - (col % tabSize);
            result.append(spaces, ' ');
            col += spaces;
        } else {
            result.push_back(c);
            col++;
            if (c == '\n' || c == '\r') col = 0;
        }
    }
    return result;
}

std::vector<std::string> StringUtilities::toLines(const std::string& str, bool preserveTokens) {
    std::vector<std::string> lines;
    std::istringstream stream(str);
    std::string line;
    while (std::getline(stream, line)) {
        if (preserveTokens) {
            lines.push_back(line);
        } else {
            std::string trimmed = line;
            // trim leading/trailing whitespace
            size_t start = trimmed.find_first_not_of(" \t\r\n");
            size_t end = trimmed.find_last_not_of(" \t\r\n");
            if (start == std::string::npos) {
                lines.push_back("");
            } else {
                lines.push_back(trimmed.substr(start, end - start + 1));
            }
        }
    }
    // Handle trailing newline case
    if (!str.empty() && str.back() == '\n') {
        lines.push_back("");
    }
    return lines;
}

std::string StringUtilities::pad(const std::string& source, char filler, int length) {
    if (static_cast<int>(source.size()) >= length) return source;
    return source + std::string(length - source.size(), filler);
}

std::string StringUtilities::trim(const std::string& original, int max) {
    if (static_cast<int>(original.size()) <= max) return original;
    if (max < 3) return original.substr(0, max);
    return original.substr(0, max - 3) + ELLIPSES;
}

std::string StringUtilities::trimMiddle(const std::string& s, int max) {
    if (static_cast<int>(s.size()) <= max) return s;
    if (max < 3) return s.substr(0, max);
    int half = (max - 3) / 2;
    int otherHalf = max - 3 - half;
    return s.substr(0, half) + ELLIPSES + s.substr(s.size() - otherHalf);
}

std::string StringUtilities::trimTrailingNulls(const std::string& s) {
    size_t end = s.size();
    while (end > 0 && s[end - 1] == '\0') end--;
    return s.substr(0, end);
}

std::string StringUtilities::indentLines(const std::string& s, const std::string& indent) {
    std::string result;
    result.reserve(s.size() + indent.size() * (std::count(s.begin(), s.end(), '\n') + 1));
    result += indent;
    for (char c : s) {
        result.push_back(c);
        if (c == '\n') result += indent;
    }
    return result;
}

std::string StringUtilities::findWord(const std::string& s, int index) {
    if (index < 0 || index >= static_cast<int>(s.size())) return "";
    // Extend forward
    int end = index;
    while (end < static_cast<int>(s.size()) && (std::isalnum(static_cast<unsigned char>(s[end])) || s[end] == '_')) end++;
    // Extend backward
    int start = index;
    while (start > 0 && (std::isalnum(static_cast<unsigned char>(s[start - 1])) || s[start - 1] == '_')) start--;
    if (start == end) return "";
    return s.substr(start, end - start);
}

std::string StringUtilities::getLastWord(const std::string& s, const std::string& separator) {
    size_t pos = s.rfind(separator);
    if (pos == std::string::npos) return s;
    return s.substr(pos + separator.size());
}

bool StringUtilities::isValidCLanguageChar(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
}

bool StringUtilities::isAsciiChar(char c) {
    return static_cast<unsigned char>(c) <= 0x7f;
}

// ---- Escape Sequences ----

std::string StringUtilities::convertEscapeSequences(const std::string& str) {
    std::string result;
    result.reserve(str.size());
    for (size_t i = 0; i < str.size(); i++) {
        if (str[i] == '\\' && i + 1 < str.size()) {
            char next = str[i + 1];
            switch (next) {
                case 'n': result.push_back('\n'); i++; break;
                case 't': result.push_back('\t'); i++; break;
                case 'r': result.push_back('\r'); i++; break;
                case '\\': result.push_back('\\'); i++; break;
                case '"': result.push_back('"'); i++; break;
                case '0': result.push_back('\0'); i++; break;
                case 'x': {
                    if (i + 3 < str.size()) {
                        char hex[3] = {str[i+2], str[i+3], 0};
                        char* end;
                        long val = strtol(hex, &end, 16);
                        if (end == hex + 2) {
                            result.push_back(static_cast<char>(val));
                            i += 3;
                        } else {
                            result.push_back(str[i]);
                        }
                    } else {
                        result.push_back(str[i]);
                    }
                    break;
                }
                default: result.push_back(str[i]); break;
            }
        } else {
            result.push_back(str[i]);
        }
    }
    return result;
}

std::string StringUtilities::convertControlCharsToEscapeSequences(const std::string& str) {
    std::string result;
    result.reserve(str.size() * 2);
    for (unsigned char c : str) {
        switch (c) {
            case '\n': result += "\\n"; break;
            case '\t': result += "\\t"; break;
            case '\r': result += "\\r"; break;
            case '\\': result += "\\\\"; break;
            case '"': result += "\\\""; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\x%02x", c);
                    result += buf;
                } else {
                    result.push_back(static_cast<char>(c));
                }
                break;
        }
    }
    return result;
}

std::string StringUtilities::mergeStrings(const std::string& string1, const std::string& string2) {
    // Simple merge: concatenate with space
    if (string1.empty()) return string2;
    if (string2.empty()) return string1;
    return string1 + " " + string2;
}

std::string StringUtilities::whitespaceToUnderscores(const std::string& s) {
    std::string result = s;
    for (char& c : result) {
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            c = '_';
        }
    }
    return result;
}

std::string StringUtilities::toFixedSize(const std::string& s, char padChar, int size) {
    if (static_cast<int>(s.size()) > size) return s.substr(0, size);
    std::string result = s;
    result.append(size - s.size(), padChar);
    return result;
}

// ---- LineWrapper ----

StringUtilities::LineWrapper::LineWrapper(int width) : width_(width) {}

StringUtilities::LineWrapper& StringUtilities::LineWrapper::append(const std::string& cs) {
    std::string word;
    std::string spaces;
    for (size_t i = 0; i < cs.size(); i++) {
        char c = cs[i];
        if (c == ' ' || c == '\t') {
            if (word.empty()) {
                spaces.push_back(c);
            } else {
                appendWord(word);
                word.clear();
                spaces.clear();
                spaces.push_back(c);
            }
        } else if (c == '\n') {
            if (!word.empty()) {
                appendWord(word);
                word.clear();
            }
            appendLinesep();
            spaces.clear();
        } else {
            if (!spaces.empty()) {
                appendSpace(spaces);
                spaces.clear();
            }
            word.push_back(c);
        }
    }
    if (!word.empty()) appendWord(word);
    return *this;
}

void StringUtilities::LineWrapper::appendWord(const std::string& word) {
    if (len_ + static_cast<int>(word.size()) > width_ && len_ > 0) {
        appendLinesep();
    }
    result_ += word;
    len_ += static_cast<int>(word.size());
}

void StringUtilities::LineWrapper::appendSpace(const std::string& space) {
    result_ += space;
    len_ += static_cast<int>(space.size());
}

void StringUtilities::LineWrapper::appendLinesep() {
    result_ += '\n';
    len_ = 0;
}

std::string StringUtilities::LineWrapper::finish() {
    return result_;
}

std::string StringUtilities::wrapToWidth(const std::string& str, int width) {
    LineWrapper wrapper(width);
    wrapper.append(str);
    return wrapper.finish();
}

} // namespace ghidra
