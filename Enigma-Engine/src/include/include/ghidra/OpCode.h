/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file OpCode.h
/// \brief Enumeration of all pcode operations
/// Translated from: ghidra.pcodeCPort.opcodes.OpCode
#pragma once

#include <string>
#include <vector>
#include <unordered_map>

namespace ghidra {

enum OpCode {
    DO_NOT_USE_ME_I_AM_ENUM_ELEMENT_ZERO,
    CPUI_COPY,
    CPUI_LOAD,
    CPUI_STORE,
    CPUI_BRANCH,
    CPUI_CBRANCH,
    CPUI_BRANCHIND,
    CPUI_CALL,
    CPUI_CALLIND,
    CPUI_CALLOTHER,
    CPUI_RETURN,
    CPUI_INT_EQUAL,
    CPUI_INT_NOTEQUAL,
    CPUI_INT_SLESS,
    CPUI_INT_SLESSEQUAL,
    CPUI_INT_LESS,
    CPUI_INT_LESSEQUAL,
    CPUI_INT_ZEXT,
    CPUI_INT_SEXT,
    CPUI_INT_ADD,
    CPUI_INT_SUB,
    CPUI_INT_CARRY,
    CPUI_INT_SCARRY,
    CPUI_INT_SBORROW,
    CPUI_INT_2COMP,
    CPUI_INT_NEGATE,
    CPUI_INT_XOR,
    CPUI_INT_AND,
    CPUI_INT_OR,
    CPUI_INT_LEFT,
    CPUI_INT_RIGHT,
    CPUI_INT_SRIGHT,
    CPUI_INT_MULT,
    CPUI_INT_DIV,
    CPUI_INT_SDIV,
    CPUI_INT_REM,
    CPUI_INT_SREM,
    CPUI_BOOL_NEGATE,
    CPUI_BOOL_XOR,
    CPUI_BOOL_AND,
    CPUI_BOOL_OR,
    CPUI_FLOAT_EQUAL,
    CPUI_FLOAT_NOTEQUAL,
    CPUI_FLOAT_LESS,
    CPUI_FLOAT_LESSEQUAL,
    CPUI_UNUSED1,
    CPUI_FLOAT_NAN,
    CPUI_FLOAT_ADD,
    CPUI_FLOAT_DIV,
    CPUI_FLOAT_MULT,
    CPUI_FLOAT_SUB,
    CPUI_FLOAT_NEG,
    CPUI_FLOAT_ABS,
    CPUI_FLOAT_SQRT,
    CPUI_FLOAT_INT2FLOAT,
    CPUI_FLOAT_FLOAT2FLOAT,
    CPUI_FLOAT_TRUNC,
    CPUI_FLOAT_CEIL,
    CPUI_FLOAT_FLOOR,
    CPUI_FLOAT_ROUND,
    CPUI_MULTIEQUAL,
    CPUI_INDIRECT,
    CPUI_PIECE,
    CPUI_SUBPIECE,
    CPUI_CAST,
    CPUI_PTRADD,
    CPUI_PTRSUB,
    CPUI_SEGMENTOP,
    CPUI_CPOOLREF,
    CPUI_NEW,
    CPUI_INSERT,
    CPUI_ZPULL,
    CPUI_POPCOUNT,
    CPUI_LZCOUNT,
    CPUI_SPULL,
    CPUI_MAX
};

inline const char* opCodeName(OpCode op) {
    switch (op) {
        case OpCode::DO_NOT_USE_ME_I_AM_ENUM_ELEMENT_ZERO: return nullptr;
        case OpCode::CPUI_COPY: return "COPY";
        case OpCode::CPUI_LOAD: return "LOAD";
        case OpCode::CPUI_STORE: return "STORE";
        case OpCode::CPUI_BRANCH: return "BRANCH";
        case OpCode::CPUI_CBRANCH: return "CBRANCH";
        case OpCode::CPUI_BRANCHIND: return "BRANCHIND";
        case OpCode::CPUI_CALL: return "CALL";
        case OpCode::CPUI_CALLIND: return "CALLIND";
        case OpCode::CPUI_CALLOTHER: return "CALLOTHER";
        case OpCode::CPUI_RETURN: return "RETURN";
        case OpCode::CPUI_INT_EQUAL: return "INT_EQUAL";
        case OpCode::CPUI_INT_NOTEQUAL: return "INT_NOTEQUAL";
        case OpCode::CPUI_INT_SLESS: return "INT_SLESS";
        case OpCode::CPUI_INT_SLESSEQUAL: return "INT_SLESSEQUAL";
        case OpCode::CPUI_INT_LESS: return "INT_LESS";
        case OpCode::CPUI_INT_LESSEQUAL: return "INT_LESSEQUAL";
        case OpCode::CPUI_INT_ZEXT: return "INT_ZEXT";
        case OpCode::CPUI_INT_SEXT: return "INT_SEXT";
        case OpCode::CPUI_INT_ADD: return "INT_ADD";
        case OpCode::CPUI_INT_SUB: return "INT_SUB";
        case OpCode::CPUI_INT_CARRY: return "INT_CARRY";
        case OpCode::CPUI_INT_SCARRY: return "INT_SCARRY";
        case OpCode::CPUI_INT_SBORROW: return "INT_SBORROW";
        case OpCode::CPUI_INT_2COMP: return "INT_2COMP";
        case OpCode::CPUI_INT_NEGATE: return "INT_NEGATE";
        case OpCode::CPUI_INT_XOR: return "INT_XOR";
        case OpCode::CPUI_INT_AND: return "INT_AND";
        case OpCode::CPUI_INT_OR: return "INT_OR";
        case OpCode::CPUI_INT_LEFT: return "INT_LEFT";
        case OpCode::CPUI_INT_RIGHT: return "INT_RIGHT";
        case OpCode::CPUI_INT_SRIGHT: return "INT_SRIGHT";
        case OpCode::CPUI_INT_MULT: return "INT_MULT";
        case OpCode::CPUI_INT_DIV: return "INT_DIV";
        case OpCode::CPUI_INT_SDIV: return "INT_SDIV";
        case OpCode::CPUI_INT_REM: return "INT_REM";
        case OpCode::CPUI_INT_SREM: return "INT_SREM";
        case OpCode::CPUI_BOOL_NEGATE: return "BOOL_NEGATE";
        case OpCode::CPUI_BOOL_XOR: return "BOOL_XOR";
        case OpCode::CPUI_BOOL_AND: return "BOOL_AND";
        case OpCode::CPUI_BOOL_OR: return "BOOL_OR";
        case OpCode::CPUI_FLOAT_EQUAL: return "FLOAT_EQUAL";
        case OpCode::CPUI_FLOAT_NOTEQUAL: return "FLOAT_NOTEQUAL";
        case OpCode::CPUI_FLOAT_LESS: return "FLOAT_LESS";
        case OpCode::CPUI_FLOAT_LESSEQUAL: return "FLOAT_LESSEQUAL";
        case OpCode::CPUI_UNUSED1: return "UNUSED1";
        case OpCode::CPUI_FLOAT_NAN: return "FLOAT_NAN";
        case OpCode::CPUI_FLOAT_ADD: return "FLOAT_ADD";
        case OpCode::CPUI_FLOAT_DIV: return "FLOAT_DIV";
        case OpCode::CPUI_FLOAT_MULT: return "FLOAT_MULT";
        case OpCode::CPUI_FLOAT_SUB: return "FLOAT_SUB";
        case OpCode::CPUI_FLOAT_NEG: return "FLOAT_NEG";
        case OpCode::CPUI_FLOAT_ABS: return "FLOAT_ABS";
        case OpCode::CPUI_FLOAT_SQRT: return "FLOAT_SQRT";
        case OpCode::CPUI_FLOAT_INT2FLOAT: return "INT2FLOAT";
        case OpCode::CPUI_FLOAT_FLOAT2FLOAT: return "FLOAT2FLOAT";
        case OpCode::CPUI_FLOAT_TRUNC: return "TRUNC";
        case OpCode::CPUI_FLOAT_CEIL: return "CEIL";
        case OpCode::CPUI_FLOAT_FLOOR: return "FLOOR";
        case OpCode::CPUI_FLOAT_ROUND: return "ROUND";
        case OpCode::CPUI_MULTIEQUAL: return "BUILD";
        case OpCode::CPUI_INDIRECT: return "DELAY_SLOT";
        case OpCode::CPUI_PIECE: return "PIECE";
        case OpCode::CPUI_SUBPIECE: return "SUBPIECE";
        case OpCode::CPUI_CAST: return "CAST";
        case OpCode::CPUI_PTRADD: return "LABEL";
        case OpCode::CPUI_PTRSUB: return "CROSSBUILD";
        case OpCode::CPUI_SEGMENTOP: return "SEGMENTOP";
        case OpCode::CPUI_CPOOLREF: return "CPOOLREF";
        case OpCode::CPUI_NEW: return "NEW";
        case OpCode::CPUI_INSERT: return "INSERT";
        case OpCode::CPUI_ZPULL: return "ZPULL";
        case OpCode::CPUI_POPCOUNT: return "POPCOUNT";
        case OpCode::CPUI_LZCOUNT: return "LZCOUNT";
        case OpCode::CPUI_SPULL: return "SPULL";
        case OpCode::CPUI_MAX: return nullptr;
    }
    return nullptr;
}

OpCode getOpCode(int ordinal);
OpCode getOpCode(const std::string& name);
OpCode opCodeFlip(OpCode op);
bool opCodeBooleanFlip(OpCode op);

} // namespace ghidra
