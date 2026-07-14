#include "CFormatter.h"
#include <sstream>
#include <vector>
#include <algorithm>

std::string CFormatter::indentStr(int level) {
    return std::string(level * INDENT_SIZE, ' ');
}

bool CFormatter::opensBlock(const std::string& trimmed) {
    if (trimmed.empty()) return false;
    if (trimmed.back() != '{') return false;
    std::string withoutBrace = trimmed.substr(0, trimmed.size() - 1);
    std::string stripped = withoutBrace;
    while (!stripped.empty() && stripped.back() == ' ')
        stripped.pop_back();
    if (stripped.empty()) return false;
    return stripped.back() == ')' || stripped.back() == ':' ||
           stripped == "do" || stripped == "else";
}

bool CFormatter::closesBlock(const std::string& trimmed) {
    return !trimmed.empty() && trimmed[0] == '}';
}

bool CFormatter::isElseLine(const std::string& trimmed) {
    return trimmed == "else" ||
           trimmed.substr(0, 5) == "else " ||
           trimmed.substr(0, 8) == "else if(" ||
           trimmed.substr(0, 9) == "else if (";
}

bool CFormatter::isDoLine(const std::string& trimmed) {
    return trimmed == "do" ||
           (trimmed.size() >= 3 && trimmed.substr(0, 3) == "do " &&
            trimmed.substr(0, 4) != "do-");
}

bool CFormatter::isCaseLabel(const std::string& trimmed) {
    return trimmed.substr(0, 5) == "case " ||
           trimmed.substr(0, 8) == "default:" ||
           trimmed == "default";
}

bool CFormatter::isDeclaration(const std::string& trimmed) {
    if (trimmed.empty()) return false;
    if (trimmed.substr(0, 4) == "int " || trimmed.substr(0, 5) == "char " ||
        trimmed.substr(0, 6) == "short " || trimmed.substr(0, 5) == "long " ||
        trimmed.substr(0, 6) == "float " || trimmed.substr(0, 7) == "double " ||
        trimmed.substr(0, 7) == "size_t " || trimmed.substr(0, 8) == "uint8_t " ||
        trimmed.substr(0, 9) == "uint16_t " || trimmed.substr(0, 9) == "uint32_t " ||
        trimmed.substr(0, 9) == "uint64_t " || trimmed.substr(0, 8) == "int8_t " ||
        trimmed.substr(0, 9) == "int16_t " || trimmed.substr(0, 9) == "int32_t " ||
        trimmed.substr(0, 9) == "int64_t " || trimmed.substr(0, 5) == "void " ||
        trimmed.substr(0, 5) == "bool " || trimmed.substr(0, 6) == "BYTE " ||
        trimmed.substr(0, 5) == "WORD " || trimmed.substr(0, 6) == "DWORD " ||
        trimmed.substr(0, 6) == "QWORD " || trimmed.substr(0, 5) == "BOOL " ||
        trimmed.substr(0, 7) == "HANDLE " || trimmed.substr(0, 6) == "LPVOID " ||
        trimmed.substr(0, 7) == "LPCSTR " || trimmed.substr(0, 5) == "LPSTR " ||
        trimmed.substr(0, 8) == "HRESULT " || trimmed.substr(0, 10) == "undefined " ||
        trimmed.substr(0, 10) == "undefined1 " || trimmed.substr(0, 10) == "undefined2 " ||
        trimmed.substr(0, 10) == "undefined4 " || trimmed.substr(0, 10) == "undefined8 " ||
        trimmed.substr(0, 5) == "byte " || trimmed.substr(0, 6) == "ushort " ||
        trimmed.substr(0, 5) == "uint " || trimmed.substr(0, 6) == "ulong " ||
        trimmed.substr(0, 9) == "longlong " || trimmed.substr(0, 10) == "ulonglong " ||
        trimmed.substr(0, 5) == "code " || trimmed.substr(0, 9) == "pointer ") {
        for (size_t i = 1; i < trimmed.size(); ++i) {
            if (trimmed[i] == '=' || trimmed[i] == ';' || trimmed[i] == ',') return true;
        }
        if (trimmed.back() == ';') return true;
    }
    return false;
}

std::string CFormatter::fixSpacing(const std::string& line) {
    std::string result;
    result.reserve(line.size());

    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];

        if (c == ' ' || c == '\t') {
            while (i + 1 < line.size() && (line[i + 1] == ' ' || line[i + 1] == '\t'))
                ++i;
            result += ' ';
            continue;
        }

        result += c;
    }

    while (!result.empty() && result.back() == ' ')
        result.pop_back();

    return result;
}

std::string CFormatter::breakLongLine(const std::string& line, int indentLevel) {
    if ((int)line.size() <= MAX_LINE_LENGTH)
        return line;

    size_t parenStart = line.find('(');
    if (parenStart == std::string::npos)
        return line;

    size_t parenEnd = line.rfind(')');
    if (parenEnd == std::string::npos || parenEnd <= parenStart + 1)
        return line;

    std::string beforeParen = line.substr(0, parenStart + 1);
    std::string args = line.substr(parenStart + 1, parenEnd - parenStart - 1);
    std::string afterParen = line.substr(parenEnd);

    if ((int)beforeParen.size() + (int)afterParen.size() + 2 >= MAX_LINE_LENGTH)
        return line;

    std::vector<std::string> argList;
    std::string current;
    int parenDepth = 0;
    for (char c : args) {
        if (c == '(') { ++parenDepth; current += c; }
        else if (c == ')') { --parenDepth; current += c; }
        else if (c == ',' && parenDepth == 0) {
            while (!current.empty() && current.back() == ' ')
                current.pop_back();
            argList.push_back(current);
            current.clear();
        } else {
            current += c;
        }
    }
    if (!current.empty()) {
        while (!current.empty() && current.back() == ' ')
            current.pop_back();
        argList.push_back(current);
    }

    if (argList.size() <= 1)
        return line;

    std::string contIndent = indentStr(indentLevel + 1);
    std::ostringstream out;
    out << beforeParen << "\n";
    for (size_t i = 0; i < argList.size(); ++i) {
        out << contIndent << " " << argList[i];
        if (i + 1 < argList.size())
            out << ",\n";
        else
            out << "\n";
    }
    out << indentStr(indentLevel) << afterParen;
    return out.str();
}

std::string CFormatter::format(const std::string& input) {
    std::istringstream stream(input);
    std::string line;
    std::vector<std::string> rawLines;

    while (std::getline(stream, line)) {
        size_t start = line.find_first_not_of(" \t");
        if (start == std::string::npos) {
            rawLines.push_back("");
        } else {
            rawLines.push_back(line.substr(start));
        }
    }

    // Merge continuation lines (pre-broken by decompiler's pretty printer)
    {
        std::vector<std::string> merged;
        bool prevInputBlank = false;
        for (size_t i = 0; i < rawLines.size(); ++i) {
            if (rawLines[i].empty()) {
                merged.push_back("");
                prevInputBlank = true;
                continue;
            }
            std::string combined = rawLines[i];
            while (i + 1 < rawLines.size()) {
                const std::string& next = rawLines[i + 1];
                if (next.empty()) break;
                if (next.rfind("code_0x", 0) == 0 || next.rfind("joined_0x", 0) == 0 ||
                    next.rfind("case ", 0) == 0 || next.rfind("default:", 0) == 0) break;
                if (combined.back() == '{' || combined.back() == '}' || combined.back() == ';') break;
                combined += " " + next;
                ++i;
            }
            merged.push_back(combined);
            prevInputBlank = false;
        }
        rawLines = std::move(merged);
    }

    std::vector<std::string> output;
    int indentLevel = 0;
    bool lastWasBlank = false;
    bool prevClosedBlock = false;

    for (size_t i = 0; i < rawLines.size(); ++i) {
        std::string trimmed = rawLines[i];

        if (trimmed.empty()) {
            if (!lastWasBlank && !output.empty()) {
                output.push_back("");
                lastWasBlank = true;
            }
            continue;
        }

        std::string commentSuffix;
        size_t commentStart = std::string::npos;
        if (trimmed.size() >= 2 && trimmed[0] == '/' && trimmed[1] == '/') {
            commentStart = 0;
        } else {
            for (size_t j = 0; j < trimmed.size(); ++j) {
                if (trimmed[j] == '"' || trimmed[j] == '\'') {
                    char q = trimmed[j];
                    ++j;
                    while (j < trimmed.size() && trimmed[j] != q) {
                        if (trimmed[j] == '\\') ++j;
                        ++j;
                    }
                } else if (j + 1 < trimmed.size() && trimmed[j] == '/' && trimmed[j+1] == '/') {
                    commentStart = j;
                    break;
                }
            }
        }

        std::string codePart = trimmed;
        std::string commentPart;
        if (commentStart != std::string::npos) {
            codePart = trimmed.substr(0, commentStart);
            commentPart = trimmed.substr(commentStart);
            while (!codePart.empty() && codePart.back() == ' ')
                codePart.pop_back();
        }

        if (isElseLine(codePart)) {
            while (!output.empty() && output.back().empty())
                output.pop_back();
            if (!output.empty() && closesBlock(output.back())) {
                std::string elseLine = output.back() + " " + codePart;
                output.pop_back();
                if (!commentPart.empty())
                    elseLine += " " + commentPart;
                if (opensBlock(codePart)) {
                    output.push_back(indentStr(indentLevel) + elseLine);
                    indentLevel++;
                } else {
                    output.push_back(indentStr(indentLevel) + elseLine);
                }
                lastWasBlank = false;
                prevClosedBlock = false;
                continue;
            }
        }

        if (closesBlock(codePart)) {
            indentLevel = std::max(0, indentLevel - 1);
            std::string fixed = fixSpacing(indentLevel > 0 ? codePart : codePart);
            std::string fullLine = indentStr(indentLevel) + fixed;
            if (!commentPart.empty())
                fullLine += " " + commentPart;
            output.push_back(fullLine);
            lastWasBlank = false;
            prevClosedBlock = true;
            continue;
        }

        if (prevClosedBlock && !isElseLine(codePart) && !opensBlock(codePart)) {
            if (!output.empty() && output.back().empty()) {
            } else {
                bool needBlank = !codePart.empty() && codePart.back() != '{';
                bool isClosing = codePart == "}" || closesBlock(codePart);
                if (needBlank && !isClosing && !isCaseLabel(codePart)) {
                    output.push_back("");
                    lastWasBlank = true;
                }
            }
        }
        prevClosedBlock = false;

        if (isCaseLabel(codePart)) {
            indentLevel = std::max(0, indentLevel - 1);
        }

        std::string fixed = fixSpacing(codePart);
        std::string fullLine = indentStr(indentLevel) + fixed;

        if (!commentPart.empty())
            fullLine += " " + commentPart;

        std::string broken = breakLongLine(fullLine, indentLevel);
        output.push_back(broken);
        if (opensBlock(codePart)) {
            indentLevel++;
        }

        lastWasBlank = false;
    }

    while (output.size() > 1 && output.back().empty())
        output.pop_back();

    std::ostringstream out;
    for (size_t i = 0; i < output.size(); ++i) {
        out << output[i];
        if (i < output.size() - 1)
            out << "\n";
    }
    return out.str();
}
