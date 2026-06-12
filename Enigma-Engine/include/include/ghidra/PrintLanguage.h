#pragma once

#include <ghidra/Address.h>
#include <ghidra/Types.h>
#include <string>
#include <vector>

namespace ghidra {

class VarnodeAST;
class PcodeOpAST;
class Funcdata;
class HighFunction;
class HighVariable;
class DataType;

class PrintLanguage {
public:
    enum LanguageType {
        LANG_C = 0,
        LANG_JAVA = 1,
        LANG_PYTHON = 2,
        LANG_UNKNOWN = 3
    };

    enum FormatFlags {
        FORMAT_NONE = 0,
        FORMAT_HEX = 1,
        FORMAT_DEC = 2,
        FORMAT_OCTAL = 4,
        FORMAT_BINARY = 8,
        FORMAT_CHAR = 16,
        FORMAT_FLOAT = 32,
        FORMAT_SIGNED = 64,
        FORMAT_UNSIGNED = 128
    };

protected:
    std::string buffer;
    LanguageType langType;
    int4 indentLevel;
    int4 lineCount;
    bool emitComments;
    bool emitLineNumbers;
    bool emitTypes;
    bool emitVariableNames;
    FormatFlags defaultFormat;

public:
    PrintLanguage(LanguageType type);
    virtual ~PrintLanguage() = default;

    virtual void reset();
    virtual void printFuncdata(Funcdata& fd) = 0;
    virtual void printHighFunction(HighFunction& hf) = 0;

    virtual void printOp(PcodeOpAST* op) = 0;
    virtual void printVarnode(VarnodeAST* vn) = 0;
    virtual void printVariable(HighVariable* hi) = 0;
    virtual void printDataType(DataType* type) = 0;

    virtual void printConstant(uintb val, int4 size) = 0;
    virtual void printAddress(const Address& addr) = 0;
    virtual void printComment(const std::string& text) = 0;

    virtual void emitIndent();
    virtual void emitNewline();
    virtual void emitSpace();
    virtual void emitOpenBrace();
    virtual void emitCloseBrace();
    virtual void emitOpenParen();
    virtual void emitCloseParen();
    virtual void emitSemi();
    virtual void emitComma();

    virtual void emitKeyword(const std::string& kw);
    virtual void emitIdentifier(const std::string& id);
    virtual void emitOperator(const std::string& op);

    const std::string& getBuffer() const { return buffer; }
    LanguageType getLanguageType() const { return langType; }
    int4 getIndentLevel() const { return indentLevel; }
    int4 getLineCount() const { return lineCount; }

    void setIndentLevel(int4 level) { indentLevel = level; }
    void setEmitComments(bool val) { emitComments = val; }
    void setEmitLineNumbers(bool val) { emitLineNumbers = val; }
    void setEmitTypes(bool val) { emitTypes = val; }
    void setEmitVariableNames(bool val) { emitVariableNames = val; }
    void setDefaultFormat(FormatFlags flags) { defaultFormat = flags; }

    bool isEmitComments() const { return emitComments; }
    bool isEmitLineNumbers() const { return emitLineNumbers; }
    bool isEmitTypes() const { return emitTypes; }
    bool isEmitVariableNames() const { return emitVariableNames; }
    FormatFlags getDefaultFormat() const { return defaultFormat; }

    void incrementIndent() { indentLevel++; }
    void decrementIndent() { if (indentLevel > 0) indentLevel--; }

    static std::string languageTypeToString(LanguageType type);
    static LanguageType stringToLanguageType(const std::string& s);
};

} // namespace ghidra
