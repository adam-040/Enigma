#include <ghidra/PrintJava.h>
#include <ghidra/Funcdata.h>
#include <ghidra/HighFunction.h>
#include <ghidra/PcodeOpAST.h>
#include <ghidra/VarnodeAST.h>
#include <ghidra/HighVariable.h>
#include <ghidra/DataType.h>
#include <ghidra/OpCode.h>
#include <sstream>
#include <iomanip>

namespace ghidra {

PrintJava::PrintJava() : PrintLanguage(LANG_JAVA) {
}

void PrintJava::reset() {
    PrintLanguage::reset();
}

void PrintJava::printFuncdata(Funcdata& fd) {
    emitClassHeader("DecompiledClass");
    emitNewline();
    emitIndent();
    emitOpenBrace();
    emitNewline();
    incrementIndent();

    emitMethodHeader(fd.getName(), "void");
    emitNewline();
    emitIndent();
    emitOpenBrace();
    emitNewline();
    incrementIndent();

    for (int i = 0; i < fd.getNumOps(); i++) {
        PcodeOpAST* op = fd.getOp(i);
        if (op) {
            emitIndent();
            printOp(op);
            emitSemi();
            emitNewline();
        }
    }

    decrementIndent();
    emitIndent();
    emitCloseBrace();
    emitNewline();

    decrementIndent();
    emitIndent();
    emitCloseBrace();
    emitNewline();
    emitClassFooter();
}

void PrintJava::printHighFunction(HighFunction& hf) {
    emitClassHeader("DecompiledClass");
    emitNewline();
    emitIndent();
    emitOpenBrace();
    emitNewline();
    incrementIndent();

    emitMethodHeader(hf.getName(), "void");
    emitNewline();
    emitIndent();
    emitOpenBrace();
    emitNewline();
    incrementIndent();

    if (emitComments) {
        emitIndent();
        printComment("High-level decompiled output");
        emitNewline();
    }

    decrementIndent();
    emitIndent();
    emitCloseBrace();
    emitNewline();

    decrementIndent();
    emitIndent();
    emitCloseBrace();
    emitNewline();
}

void PrintJava::printOp(PcodeOpAST* op) {
    if (!op) return;

    VarnodeAST* output = static_cast<VarnodeAST*>(op->getOutput());
    if (output) {
        printVarnode(output);
        emitSpace();
        emitOperator("=");
        emitSpace();
    }

    emitKeyword(getOpMnemonic(op->getOpcode()));
    emitOpenParen();

    for (int i = 0; i < op->getNumInputs(); i++) {
        if (i > 0) emitComma();
        VarnodeAST* input = static_cast<VarnodeAST*>(op->getInput(i));
        if (input) {
            printVarnode(input);
        }
    }

    emitCloseParen();
}

void PrintJava::printVarnode(VarnodeAST* vn) {
    if (!vn) return;

    if (vn->isConstant()) {
        printConstant(vn->getOffset(), vn->getSize());
    } else if (vn->isUnique()) {
        emitIdentifier("unique_");
        std::ostringstream oss;
        oss << vn->getUniqueId();
        buffer += oss.str();
    } else {
        HighVariable* hi = vn->getHigh();
        if (hi && emitVariableNames) {
            emitIdentifier("var_" + std::to_string(vn->getUniqueId()));
        } else {
            emitIdentifier("vn_" + std::to_string(vn->getUniqueId()));
        }
    }
}

void PrintJava::printVariable(HighVariable* hi) {
    if (!hi) return;

    if (emitTypes) {
        emitIdentifier("int");
        emitSpace();
    }
    VarnodeAST* rep = hi->getRepresentative();
    if (rep) {
        emitIdentifier("var_" + std::to_string(rep->getUniqueId()));
    } else {
        emitIdentifier("var_unknown");
    }
}

void PrintJava::printDataType(DataType* type) {
    if (!type) return;
    emitIdentifier(getDataTypeName(type));
}

void PrintJava::printConstant(uintb val, int4 size) {
    buffer += formatConstant(val, size);
}

void PrintJava::printAddress(const Address& addr) {
    if (!addr.getAddressSpace()) {
        buffer += "invalid";
        return;
    }
    std::ostringstream oss;
    oss << addr.getAddressSpace()->getName() << ":0x"
        << std::hex << addr.getOffset();
    buffer += oss.str();
}

void PrintJava::printComment(const std::string& text) {
    buffer += "// " + text;
}

void PrintJava::emitClassHeader(const std::string& className) {
    emitKeyword("public");
    emitSpace();
    emitKeyword("class");
    emitSpace();
    emitIdentifier(className);
    emitSpace();
}

void PrintJava::emitClassFooter() {
}

void PrintJava::emitMethodHeader(const std::string& name, const std::string& returnType) {
    emitKeyword("public");
    emitSpace();
    emitKeyword("static");
    emitSpace();
    emitIdentifier(returnType);
    emitSpace();
    emitIdentifier(name);
    emitOpenParen();
    emitCloseParen();
    emitSpace();
}

void PrintJava::emitMethodFooter() {
}

std::string PrintJava::formatConstant(uintb val, int4 size) const {
    std::ostringstream oss;

    if ((defaultFormat & FORMAT_HEX) != 0) {
        oss << "0x" << std::hex << val;
    } else if ((defaultFormat & FORMAT_DEC) != 0) {
        oss << std::dec << val;
    } else {
        oss << "0x" << std::hex << val;
    }

    if (size == 1) {
        oss << "b";
    } else if (size == 2) {
        oss << "s";
    } else if (size >= 8) {
        oss << "L";
    }

    return oss.str();
}

std::string PrintJava::getOpMnemonic(int opcode) const {
    switch (opcode) {
        case static_cast<int>(OpCode::CPUI_COPY): return "copy";
        case static_cast<int>(OpCode::CPUI_INT_ADD): return "add";
        case static_cast<int>(OpCode::CPUI_INT_SUB): return "sub";
        case static_cast<int>(OpCode::CPUI_INT_MULT): return "mult";
        case static_cast<int>(OpCode::CPUI_INT_DIV): return "div";
        case static_cast<int>(OpCode::CPUI_INT_AND): return "and";
        case static_cast<int>(OpCode::CPUI_INT_OR): return "or";
        case static_cast<int>(OpCode::CPUI_INT_XOR): return "xor";
        case static_cast<int>(OpCode::CPUI_INT_LEFT): return "left";
        case static_cast<int>(OpCode::CPUI_INT_RIGHT): return "right";
        case static_cast<int>(OpCode::CPUI_INT_EQUAL): return "equal";
        case static_cast<int>(OpCode::CPUI_INT_NOTEQUAL): return "notequal";
        case static_cast<int>(OpCode::CPUI_INT_SLESS): return "sless";
        case static_cast<int>(OpCode::CPUI_INT_LESS): return "less";
        case static_cast<int>(OpCode::CPUI_BOOL_AND): return "boolAnd";
        case static_cast<int>(OpCode::CPUI_BOOL_OR): return "boolOr";
        case static_cast<int>(OpCode::CPUI_LOAD): return "load";
        case static_cast<int>(OpCode::CPUI_STORE): return "store";
        case static_cast<int>(OpCode::CPUI_CALL): return "call";
        case static_cast<int>(OpCode::CPUI_RETURN): return "return";
        default: return "op" + std::to_string(opcode);
    }
}

std::string PrintJava::getDataTypeName(DataType* type) const {
    if (!type) return "unknown";
    std::string name = type->getName();
    if (name == "int") return "int";
    if (name == "uint") return "int";
    if (name == "long") return "long";
    if (name == "ulong") return "long";
    if (name == "float") return "float";
    if (name == "double") return "double";
    if (name == "char") return "char";
    if (name == "bool") return "boolean";
    return "Object";
}

} // namespace ghidra
