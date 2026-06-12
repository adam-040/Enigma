#include <ghidra/PrintC.h>
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

PrintC::PrintC() : PrintLanguage(LANG_C) {
}

void PrintC::reset() {
    PrintLanguage::reset();
}

void PrintC::printFuncdata(Funcdata& fd) {
    emitFunctionHeader(fd.getName(), "void");
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
    emitFunctionFooter();
}

void PrintC::printHighFunction(HighFunction& hf) {
    emitFunctionHeader(hf.getName(), "void");
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
}

void PrintC::printOp(PcodeOpAST* op) {
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

void PrintC::printVarnode(VarnodeAST* vn) {
    if (!vn) return;

    if (vn->isConstant()) {
        // Use reinterpretted uint64_t to avoid negative cpp_int issues
        uint64_t rawOffset = static_cast<uint64_t>(vn->getOffset());
        printConstant(rawOffset, vn->getSize());
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

void PrintC::printVariable(HighVariable* hi) {
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

void PrintC::printDataType(DataType* type) {
    if (!type) return;
    emitIdentifier(getDataTypeName(type));
}

void PrintC::printConstant(uintb val, int4 size) {
    buffer += formatConstant(val, size);
}

void PrintC::printAddress(const Address& addr) {
    if (!addr.getAddressSpace()) {
        buffer += "invalid";
        return;
    }
    std::ostringstream oss;
    oss << addr.getAddressSpace()->getName() << ":0x"
        << std::hex << addr.getOffset();
    buffer += oss.str();
}

void PrintC::printComment(const std::string& text) {
    buffer += "/* " + text + " */";
}

void PrintC::emitFunctionHeader(const std::string& name, const std::string& returnType) {
    emitIdentifier(returnType);
    emitSpace();
    emitIdentifier(name);
    emitOpenParen();
    emitCloseParen();
    emitSpace();
}

void PrintC::emitFunctionFooter() {
}

void PrintC::emitAssignment(const std::string& dest, const std::string& src) {
    emitIdentifier(dest);
    emitSpace();
    emitOperator("=");
    emitSpace();
    emitIdentifier(src);
    emitSemi();
}

void PrintC::emitDeclaration(const std::string& type, const std::string& name) {
    emitIdentifier(type);
    emitSpace();
    emitIdentifier(name);
    emitSemi();
}

void PrintC::emitReturn(const std::string& value) {
    emitKeyword("return");
    emitSpace();
    emitIdentifier(value);
    emitSemi();
}

std::string PrintC::formatConstant(uintb val, int4 size) const {
    std::ostringstream oss;

    // Convert to uint64_t for formatting to avoid boost::multiprecision hex printing issues
    uint64_t uval = static_cast<uint64_t>(val);

    if ((defaultFormat & FORMAT_HEX) != 0) {
        oss << "0x" << std::hex << uval;
    } else if ((defaultFormat & FORMAT_DEC) != 0) {
        oss << std::dec << uval;
    } else if ((defaultFormat & FORMAT_OCTAL) != 0) {
        oss << "0" << std::oct << uval;
    } else if ((defaultFormat & FORMAT_BINARY) != 0) {
        for (int i = (size * 8) - 1; i >= 0; i--) {
            oss << ((uval >> i) & 1);
        }
    } else {
        oss << "0x" << std::hex << uval;
    }

    return oss.str();
}

std::string PrintC::getOpMnemonic(int opcode) const {
    switch (opcode) {
        case static_cast<int>(OpCode::CPUI_COPY): return "COPY";
        case static_cast<int>(OpCode::CPUI_INT_ADD): return "ADD";
        case static_cast<int>(OpCode::CPUI_INT_SUB): return "SUB";
        case static_cast<int>(OpCode::CPUI_INT_MULT): return "MULT";
        case static_cast<int>(OpCode::CPUI_INT_DIV): return "DIV";
        case static_cast<int>(OpCode::CPUI_INT_REM): return "REM";
        case static_cast<int>(OpCode::CPUI_INT_SDIV): return "SDIV";
        case static_cast<int>(OpCode::CPUI_INT_SREM): return "SREM";
        case static_cast<int>(OpCode::CPUI_INT_AND): return "AND";
        case static_cast<int>(OpCode::CPUI_INT_OR): return "OR";
        case static_cast<int>(OpCode::CPUI_INT_XOR): return "XOR";
        case static_cast<int>(OpCode::CPUI_INT_LEFT): return "LEFT";
        case static_cast<int>(OpCode::CPUI_INT_RIGHT): return "RIGHT";
        case static_cast<int>(OpCode::CPUI_INT_SRIGHT): return "SRIGHT";
        case static_cast<int>(OpCode::CPUI_INT_ZEXT): return "ZEXT";
        case static_cast<int>(OpCode::CPUI_INT_SEXT): return "SEXT";
        case static_cast<int>(OpCode::CPUI_INT_EQUAL): return "EQUAL";
        case static_cast<int>(OpCode::CPUI_INT_NOTEQUAL): return "NOTEQUAL";
        case static_cast<int>(OpCode::CPUI_INT_SLESS): return "SLESS";
        case static_cast<int>(OpCode::CPUI_INT_SLESSEQUAL): return "SLESSEQUAL";
        case static_cast<int>(OpCode::CPUI_INT_LESS): return "LESS";
        case static_cast<int>(OpCode::CPUI_INT_LESSEQUAL): return "LESSEQUAL";
        case static_cast<int>(OpCode::CPUI_BOOL_AND): return "BOOL_AND";
        case static_cast<int>(OpCode::CPUI_BOOL_OR): return "BOOL_OR";
        case static_cast<int>(OpCode::CPUI_BOOL_XOR): return "BOOL_XOR";
        case static_cast<int>(OpCode::CPUI_BOOL_NEGATE): return "BOOL_NEGATE";
        case static_cast<int>(OpCode::CPUI_LOAD): return "LOAD";
        case static_cast<int>(OpCode::CPUI_STORE): return "STORE";
        case static_cast<int>(OpCode::CPUI_BRANCH): return "BRANCH";
        case static_cast<int>(OpCode::CPUI_CBRANCH): return "CBRANCH";
        case static_cast<int>(OpCode::CPUI_BRANCHIND): return "BRANCHIND";
        case static_cast<int>(OpCode::CPUI_CALL): return "CALL";
        case static_cast<int>(OpCode::CPUI_CALLIND): return "CALLIND";
        case static_cast<int>(OpCode::CPUI_RETURN): return "RETURN";
        default: return "OP_" + std::to_string(opcode);
    }
}

std::string PrintC::getDataTypeName(DataType* type) const {
    if (!type) return "unknown";
    return type->getName();
}

} // namespace ghidra
