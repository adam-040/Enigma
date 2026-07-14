#ifndef CFORMATTER_H
#define CFORMATTER_H

#include <string>

class CFormatter {
public:
    static std::string format(const std::string& input);

private:
    static const int INDENT_SIZE = 4;
    static const int MAX_LINE_LENGTH = 100;

    static std::string indentStr(int level);
    static bool opensBlock(const std::string& trimmed);
    static bool closesBlock(const std::string& trimmed);
    static bool isElseLine(const std::string& trimmed);
    static bool isDoLine(const std::string& trimmed);
    static bool isCaseLabel(const std::string& trimmed);
    static bool isDeclaration(const std::string& trimmed);
    static std::string fixSpacing(const std::string& line);
    static std::string breakLongLine(const std::string& line, int indentLevel);
};

#endif
