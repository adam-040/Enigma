/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file OpBehavior.h
/// \brief Classes for describing the behavior of individual p-code operations
#pragma once

#include <ghidra/Types.h>
#include "OpCode.h"
#include "LowlevelError.h"
#include <vector>

namespace ghidra {

class Translate;  // Forward declaration

/// This exception is thrown when emulation evaluation of an operator fails
struct EvaluationError : public LowlevelError {
  EvaluationError(const std::string& s) : LowlevelError(s) {}
};

/// \brief Class encapsulating the action/behavior of specific pcode opcodes
class OpBehavior {
  OpCode opcode;
  bool isunary;
  bool isspecial;
public:
  OpBehavior(OpCode opc, bool isun) : opcode(opc), isunary(isun), isspecial(false) {}
  OpBehavior(OpCode opc, bool isun, bool isspec) : opcode(opc), isunary(isun), isspecial(isspec) {}
  virtual ~OpBehavior() {}

  OpCode getOpcode() const { return opcode; }
  bool isSpecial() const { return isspecial; }
  bool isUnary() const { return isunary; }

  virtual uintb evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const;
  virtual uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const;
  virtual uintb evaluateTernary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2, uintb in3) const;
  virtual uintb recoverInputBinary(int32_t slot, int32_t sizeout, uintb out, int32_t sizein, uintb in) const;
  virtual uintb recoverInputUnary(int32_t sizeout, uintb out, int32_t sizein) const;

  static void registerInstructions(std::vector<OpBehavior*>& inst, const Translate* trans);
};

// --- Concrete OpBehavior subclasses ---

class OpBehaviorCopy : public OpBehavior {
public:
  OpBehaviorCopy() : OpBehavior(CPUI_COPY, true) {}
  uintb evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const override;
  uintb recoverInputUnary(int32_t sizeout, uintb out, int32_t sizein) const override;
};

class OpBehaviorEqual : public OpBehavior {
public:
  OpBehaviorEqual() : OpBehavior(CPUI_INT_EQUAL, false) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
};

class OpBehaviorNotEqual : public OpBehavior {
public:
  OpBehaviorNotEqual() : OpBehavior(CPUI_INT_NOTEQUAL, false) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
};

class OpBehaviorIntSless : public OpBehavior {
public:
  OpBehaviorIntSless() : OpBehavior(CPUI_INT_SLESS, false) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
};

class OpBehaviorIntSlessEqual : public OpBehavior {
public:
  OpBehaviorIntSlessEqual() : OpBehavior(CPUI_INT_SLESSEQUAL, false) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
};

class OpBehaviorIntLess : public OpBehavior {
public:
  OpBehaviorIntLess() : OpBehavior(CPUI_INT_LESS, false) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
};

class OpBehaviorIntLessEqual : public OpBehavior {
public:
  OpBehaviorIntLessEqual() : OpBehavior(CPUI_INT_LESSEQUAL, false) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
};

class OpBehaviorIntZext : public OpBehavior {
public:
  OpBehaviorIntZext() : OpBehavior(CPUI_INT_ZEXT, true) {}
  uintb evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const override;
  uintb recoverInputUnary(int32_t sizeout, uintb out, int32_t sizein) const override;
};

class OpBehaviorIntSext : public OpBehavior {
public:
  OpBehaviorIntSext() : OpBehavior(CPUI_INT_SEXT, true) {}
  uintb evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const override;
  uintb recoverInputUnary(int32_t sizeout, uintb out, int32_t sizein) const override;
};

class OpBehaviorIntAdd : public OpBehavior {
public:
  OpBehaviorIntAdd() : OpBehavior(CPUI_INT_ADD, false) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
  uintb recoverInputBinary(int32_t slot, int32_t sizeout, uintb out, int32_t sizein, uintb in) const override;
};

class OpBehaviorIntSub : public OpBehavior {
public:
  OpBehaviorIntSub() : OpBehavior(CPUI_INT_SUB, false) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
  uintb recoverInputBinary(int32_t slot, int32_t sizeout, uintb out, int32_t sizein, uintb in) const override;
};

class OpBehaviorIntCarry : public OpBehavior {
public:
  OpBehaviorIntCarry() : OpBehavior(CPUI_INT_CARRY, false) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
};

class OpBehaviorIntScarry : public OpBehavior {
public:
  OpBehaviorIntScarry() : OpBehavior(CPUI_INT_SCARRY, false) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
};

class OpBehaviorIntSborrow : public OpBehavior {
public:
  OpBehaviorIntSborrow() : OpBehavior(CPUI_INT_SBORROW, false) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
};

class OpBehaviorInt2Comp : public OpBehavior {
public:
  OpBehaviorInt2Comp() : OpBehavior(CPUI_INT_2COMP, true) {}
  uintb evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const override;
  uintb recoverInputUnary(int32_t sizeout, uintb out, int32_t sizein) const override;
};

class OpBehaviorIntNegate : public OpBehavior {
public:
  OpBehaviorIntNegate() : OpBehavior(CPUI_INT_NEGATE, true) {}
  uintb evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const override;
  uintb recoverInputUnary(int32_t sizeout, uintb out, int32_t sizein) const override;
};

class OpBehaviorIntXor : public OpBehavior {
public:
  OpBehaviorIntXor() : OpBehavior(CPUI_INT_XOR, false) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
};

class OpBehaviorIntAnd : public OpBehavior {
public:
  OpBehaviorIntAnd() : OpBehavior(CPUI_INT_AND, false) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
};

class OpBehaviorIntOr : public OpBehavior {
public:
  OpBehaviorIntOr() : OpBehavior(CPUI_INT_OR, false) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
};

class OpBehaviorIntLeft : public OpBehavior {
public:
  OpBehaviorIntLeft() : OpBehavior(CPUI_INT_LEFT, false) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
  uintb recoverInputBinary(int32_t slot, int32_t sizeout, uintb out, int32_t sizein, uintb in) const override;
};

class OpBehaviorIntRight : public OpBehavior {
public:
  OpBehaviorIntRight() : OpBehavior(CPUI_INT_RIGHT, false) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
  uintb recoverInputBinary(int32_t slot, int32_t sizeout, uintb out, int32_t sizein, uintb in) const override;
};

class OpBehaviorIntSright : public OpBehavior {
public:
  OpBehaviorIntSright() : OpBehavior(CPUI_INT_SRIGHT, false) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
  uintb recoverInputBinary(int32_t slot, int32_t sizeout, uintb out, int32_t sizein, uintb in) const override;
};

class OpBehaviorIntMult : public OpBehavior {
public:
  OpBehaviorIntMult() : OpBehavior(CPUI_INT_MULT, false) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
};

class OpBehaviorIntDiv : public OpBehavior {
public:
  OpBehaviorIntDiv() : OpBehavior(CPUI_INT_DIV, false) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
};

class OpBehaviorIntSdiv : public OpBehavior {
public:
  OpBehaviorIntSdiv() : OpBehavior(CPUI_INT_SDIV, false) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
};

class OpBehaviorIntRem : public OpBehavior {
public:
  OpBehaviorIntRem() : OpBehavior(CPUI_INT_REM, false) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
};

class OpBehaviorIntSrem : public OpBehavior {
public:
  OpBehaviorIntSrem() : OpBehavior(CPUI_INT_SREM, false) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
};

class OpBehaviorBoolNegate : public OpBehavior {
public:
  OpBehaviorBoolNegate() : OpBehavior(CPUI_BOOL_NEGATE, true) {}
  uintb evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const override;
};

class OpBehaviorBoolXor : public OpBehavior {
public:
  OpBehaviorBoolXor() : OpBehavior(CPUI_BOOL_XOR, false) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
};

class OpBehaviorBoolAnd : public OpBehavior {
public:
  OpBehaviorBoolAnd() : OpBehavior(CPUI_BOOL_AND, false) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
};

class OpBehaviorBoolOr : public OpBehavior {
public:
  OpBehaviorBoolOr() : OpBehavior(CPUI_BOOL_OR, false) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
};

class OpBehaviorFloatEqual : public OpBehavior {
  const Translate* translate;
public:
  OpBehaviorFloatEqual(const Translate* trans) : OpBehavior(CPUI_FLOAT_EQUAL, false), translate(trans) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
};

class OpBehaviorFloatNotEqual : public OpBehavior {
  const Translate* translate;
public:
  OpBehaviorFloatNotEqual(const Translate* trans) : OpBehavior(CPUI_FLOAT_NOTEQUAL, false), translate(trans) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
};

class OpBehaviorFloatLess : public OpBehavior {
  const Translate* translate;
public:
  OpBehaviorFloatLess(const Translate* trans) : OpBehavior(CPUI_FLOAT_LESS, false), translate(trans) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
};

class OpBehaviorFloatLessEqual : public OpBehavior {
  const Translate* translate;
public:
  OpBehaviorFloatLessEqual(const Translate* trans) : OpBehavior(CPUI_FLOAT_LESSEQUAL, false), translate(trans) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
};

class OpBehaviorFloatNan : public OpBehavior {
  const Translate* translate;
public:
  OpBehaviorFloatNan(const Translate* trans) : OpBehavior(CPUI_FLOAT_NAN, true), translate(trans) {}
  uintb evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const override;
};

class OpBehaviorFloatAdd : public OpBehavior {
  const Translate* translate;
public:
  OpBehaviorFloatAdd(const Translate* trans) : OpBehavior(CPUI_FLOAT_ADD, false), translate(trans) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
};

class OpBehaviorFloatDiv : public OpBehavior {
  const Translate* translate;
public:
  OpBehaviorFloatDiv(const Translate* trans) : OpBehavior(CPUI_FLOAT_DIV, false), translate(trans) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
};

class OpBehaviorFloatMult : public OpBehavior {
  const Translate* translate;
public:
  OpBehaviorFloatMult(const Translate* trans) : OpBehavior(CPUI_FLOAT_MULT, false), translate(trans) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
};

class OpBehaviorFloatSub : public OpBehavior {
  const Translate* translate;
public:
  OpBehaviorFloatSub(const Translate* trans) : OpBehavior(CPUI_FLOAT_SUB, false), translate(trans) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
};

class OpBehaviorFloatNeg : public OpBehavior {
  const Translate* translate;
public:
  OpBehaviorFloatNeg(const Translate* trans) : OpBehavior(CPUI_FLOAT_NEG, true), translate(trans) {}
  uintb evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const override;
};

class OpBehaviorFloatAbs : public OpBehavior {
  const Translate* translate;
public:
  OpBehaviorFloatAbs(const Translate* trans) : OpBehavior(CPUI_FLOAT_ABS, true), translate(trans) {}
  uintb evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const override;
};

class OpBehaviorFloatSqrt : public OpBehavior {
  const Translate* translate;
public:
  OpBehaviorFloatSqrt(const Translate* trans) : OpBehavior(CPUI_FLOAT_SQRT, true), translate(trans) {}
  uintb evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const override;
};

class OpBehaviorFloatInt2Float : public OpBehavior {
  const Translate* translate;
public:
  OpBehaviorFloatInt2Float(const Translate* trans) : OpBehavior(CPUI_FLOAT_INT2FLOAT, true), translate(trans) {}
  uintb evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const override;
};

class OpBehaviorFloatFloat2Float : public OpBehavior {
  const Translate* translate;
public:
  OpBehaviorFloatFloat2Float(const Translate* trans) : OpBehavior(CPUI_FLOAT_FLOAT2FLOAT, true), translate(trans) {}
  uintb evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const override;
};

class OpBehaviorFloatTrunc : public OpBehavior {
  const Translate* translate;
public:
  OpBehaviorFloatTrunc(const Translate* trans) : OpBehavior(CPUI_FLOAT_TRUNC, true), translate(trans) {}
  uintb evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const override;
};

class OpBehaviorFloatCeil : public OpBehavior {
  const Translate* translate;
public:
  OpBehaviorFloatCeil(const Translate* trans) : OpBehavior(CPUI_FLOAT_CEIL, true), translate(trans) {}
  uintb evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const override;
};

class OpBehaviorFloatFloor : public OpBehavior {
  const Translate* translate;
public:
  OpBehaviorFloatFloor(const Translate* trans) : OpBehavior(CPUI_FLOAT_FLOOR, true), translate(trans) {}
  uintb evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const override;
};

class OpBehaviorFloatRound : public OpBehavior {
  const Translate* translate;
public:
  OpBehaviorFloatRound(const Translate* trans) : OpBehavior(CPUI_FLOAT_ROUND, true), translate(trans) {}
  uintb evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const override;
};

class OpBehaviorPiece : public OpBehavior {
public:
  OpBehaviorPiece() : OpBehavior(CPUI_PIECE, false) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
};

class OpBehaviorSubpiece : public OpBehavior {
public:
  OpBehaviorSubpiece() : OpBehavior(CPUI_SUBPIECE, false) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
};

class OpBehaviorPtradd : public OpBehavior {
public:
  OpBehaviorPtradd() : OpBehavior(CPUI_PTRADD, false) {}
  uintb evaluateTernary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2, uintb in3) const override;
};

class OpBehaviorPtrsub : public OpBehavior {
public:
  OpBehaviorPtrsub() : OpBehavior(CPUI_PTRSUB, false) {}
  uintb evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const override;
};

class OpBehaviorPopcount : public OpBehavior {
public:
  OpBehaviorPopcount() : OpBehavior(CPUI_POPCOUNT, true) {}
  uintb evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const override;
};

class OpBehaviorLzcount : public OpBehavior {
public:
  OpBehaviorLzcount() : OpBehavior(CPUI_LZCOUNT, true) {}
  uintb evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const override;
};

} // namespace ghidra
