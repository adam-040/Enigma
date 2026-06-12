/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file OperandType.h
/// \brief Helper class for testing operand related flags in an integer
/// Translated from: ghidra.program.model.lang.OperandType
#pragma once

#include <string>

namespace ghidra {

struct OperandType {
    static constexpr int READ      = 0x00000001;
    static constexpr int WRITE     = 0x00000002;
    static constexpr int INDIRECT  = 0x00000004;
    static constexpr int IMMEDIATE = 0x00000008;
    static constexpr int RELATIVE  = 0x00000010;
    static constexpr int IMPLICIT  = 0x00000020;
    static constexpr int CODE      = 0x00000040;
    static constexpr int DATA      = 0x00000080;
    static constexpr int PORT      = 0x00000100;
    static constexpr int REGISTER  = 0x00000200;
    static constexpr int LIST      = 0x00000400;
    static constexpr int FLAG      = 0x00000800;
    static constexpr int TEXT      = 0x00001000;
    static constexpr int ADDRESS   = 0x00002000;
    static constexpr int SCALAR    = 0x00004000;
    static constexpr int BIT       = 0x00008000;
    static constexpr int BYTE      = 0x00010000;
    static constexpr int WORD      = 0x00020000;
    static constexpr int QUADWORD  = 0x00040000;
    static constexpr int SIGNED    = 0x00080000;
    static constexpr int FLOAT     = 0x00100000;
    static constexpr int COP       = 0x00200000;
    static constexpr int DYNAMIC   = 0x00400000;

    static bool doesRead(int t)          { return (t & READ) != 0; }
    static bool doesWrite(int t)         { return (t & WRITE) != 0; }
    static bool isIndirect(int t)        { return (t & INDIRECT) != 0; }
    static bool isImmediate(int t)       { return (t & IMMEDIATE) != 0; }
    static bool isRelative(int t)        { return (t & RELATIVE) != 0; }
    static bool isImplicit(int t)        { return (t & IMPLICIT) != 0; }
    static bool isCodeReference(int t)   { return (t & CODE) != 0; }
    static bool isDataReference(int t)   { return (t & DATA) != 0; }
    static bool isPort(int t)            { return (t & PORT) != 0; }
    static bool isRegister(int t)        { return (t & REGISTER) != 0; }
    static bool isList(int t)            { return (t & LIST) != 0; }
    static bool isFlag(int t)            { return (t & FLAG) != 0; }
    static bool isText(int t)            { return (t & TEXT) != 0; }
    static bool isAddress(int t)         { return (t & ADDRESS) != 0; }
    static bool isScalar(int t)          { return (t & SCALAR) != 0; }
    static bool isBit(int t)             { return (t & BIT) != 0; }
    static bool isByte(int t)            { return (t & BYTE) != 0; }
    static bool isWord(int t)            { return (t & WORD) != 0; }
    static bool isQuadWord(int t)        { return (t & QUADWORD) != 0; }
    static bool isSigned(int t)          { return (t & SIGNED) != 0; }
    static bool isFloat(int t)           { return (t & FLOAT) != 0; }
    static bool isCoProcessor(int t)     { return (t & COP) != 0; }
    static bool isDynamic(int t)         { return (t & DYNAMIC) != 0; }
    static bool isScalarAsAddress(int t) { return isAddress(t) && isScalar(t); }

    static std::string toString(int operandType);
};

inline std::string OperandType::toString(int t) {
    std::string buf;
    auto append = [&buf](const char* s) {
        if (!buf.empty()) buf += " | ";
        buf += s;
    };
    if (isAddress(t))    append("ADDR");
    if (isScalar(t))     append("SCAL");
    if (isPort(t))       append("PORT");
    if (isRegister(t))   append("REG");
    if (isList(t))       append("LIST");
    if (isFlag(t))       append("FLAG");
    if (isText(t))       append("TEXT");
    if (isCodeReference(t)) append("CODE");
    if (isDataReference(t)) append("DATA");
    if (isBit(t))        append("BIT");
    if (isByte(t))       append("BYTE");
    if (isWord(t))       append("WORD");
    if (isQuadWord(t))   append("QUAD");
    if (isSigned(t))     append("SIGN");
    if (isFloat(t))      append("FLT");
    if (isIndirect(t))   append("IND");
    if (isImmediate(t))  append("IMM");
    if (isRelative(t))   append("REL");
    if (isImplicit(t))   append("IMPL");
    if (doesRead(t))     append("READ");
    if (doesWrite(t))    append("WRTE");
    if (isCoProcessor(t)) append("COP");
    if (isDynamic(t))    append("DYN");
    return buf;
}

} // namespace ghidra
