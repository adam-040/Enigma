#include <ghidra/PrintLanguage.h>
#include <sstream>

namespace ghidra {

PrintLanguage::PrintLanguage(LanguageType type)
    : langType(type), indentLevel(0), lineCount(0),
      emitComments(true), emitLineNumbers(false), emitTypes(true),
      emitVariableNames(true), defaultFormat(FORMAT_HEX) {
}

void PrintLanguage::reset() {
    buffer.clear();
    indentLevel = 0;
    lineCount = 0;
}

void PrintLanguage::emitIndent() {
    for (int4 i = 0; i < indentLevel; i++) {
        buffer += "    ";
    }
}

void PrintLanguage::emitNewline() {
    buffer += "\n";
    lineCount++;
}

void PrintLanguage::emitSpace() {
    buffer += " ";
}

void PrintLanguage::emitOpenBrace() {
    buffer += "{";
}

void PrintLanguage::emitCloseBrace() {
    buffer += "}";
}

void PrintLanguage::emitOpenParen() {
    buffer += "(";
}

void PrintLanguage::emitCloseParen() {
    buffer += ")";
}

void PrintLanguage::emitSemi() {
    buffer += ";";
}

void PrintLanguage::emitComma() {
    buffer += ", ";
}

void PrintLanguage::emitKeyword(const std::string& kw) {
    buffer += kw;
}

void PrintLanguage::emitIdentifier(const std::string& id) {
    buffer += id;
}

void PrintLanguage::emitOperator(const std::string& op) {
    buffer += op;
}

std::string PrintLanguage::languageTypeToString(LanguageType type) {
    switch (type) {
        case LANG_C: return "C";
        case LANG_JAVA: return "Java";
        case LANG_PYTHON: return "Python";
        default: return "Unknown";
    }
}

PrintLanguage::LanguageType PrintLanguage::stringToLanguageType(const std::string& s) {
    if (s == "C") return LANG_C;
    if (s == "Java" || s == "java") return LANG_JAVA;
    if (s == "Python" || s == "python") return LANG_PYTHON;
    return LANG_UNKNOWN;
}

} // namespace ghidra
