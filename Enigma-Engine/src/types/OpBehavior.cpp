#include "ghidra/OpBehavior.h"
#include "ghidra/OpCode.h"
#include "ghidra/Translate.h"
#include <limits>

namespace ghidra {

static inline uintb calc_mask(int32_t size) {
    if (size <= 0) return 0;
    return (uintb(1) << (size * 8)) - 1;
}

static inline bool signbit_negative(const uintb& val, int32_t size) {
    if (size <= 0) return false;
    return (val >> (size * 8 - 1)) != 0;
}

static inline uintb uintb_negate(const uintb& in, int32_t size) {
    return (~in) & calc_mask(size);
}

static inline uintb sign_extend(const uintb& in, int32_t sizein, int32_t sizeout) {
    if (sizein <= 0 || sizeout <= 0) return in;
    uintb mask = calc_mask(sizein);
    uintb res = in & mask;
    uintb sign_bit = uintb(1) << (sizein * 8 - 1);
    if (res & sign_bit)
        res |= ~mask;
    return res & calc_mask(sizeout);
}

static inline int64_t sign_extend_signed(const uintb& in, int32_t bit) {
    if (bit <= 0) return static_cast<int64_t>(in);
    uintb mask = (uintb(1) << (bit + 1)) - 1;
    uintb res = in & mask;
    uintb sign_bit = uintb(1) << bit;
    if (res & sign_bit)
        res |= ~mask;
    return static_cast<int64_t>(res);
}

static inline int32_t popcount(const uintb& val) {
    if (val == 0) return 0;
    if (val <= (std::numeric_limits<uint64_t>::max)())
        return static_cast<int32_t>(__builtin_popcountll(static_cast<uint64_t>(val)));
    int32_t count = 0;
    uintb v = val;
    while (v > 0) {
        v &= v - 1;
        count++;
    }
    return count;
}

static inline int32_t count_leading_zeros(const uintb& val) {
    if (val == 0) return 0;
    if (val <= (std::numeric_limits<uint64_t>::max)())
        return static_cast<int32_t>(__builtin_clzll(static_cast<uint64_t>(val)));
    int32_t msb_idx = static_cast<int32_t>(boost::multiprecision::msb(val));
    return 1024 - msb_idx - 1;
}

uintb OpBehavior::evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const {
    throw LowlevelError(std::string("Unary emulation unimplemented for ") + opCodeName(opcode));
}

uintb OpBehavior::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    throw LowlevelError(std::string("Binary emulation unimplemented for ") + opCodeName(opcode));
}

uintb OpBehavior::evaluateTernary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2, uintb in3) const {
    throw LowlevelError(std::string("Ternary emulation unimplemented for ") + opCodeName(opcode));
}

uintb OpBehavior::recoverInputUnary(int32_t sizeout, uintb out, int32_t sizein) const {
    throw LowlevelError("Cannot recover input parameter without loss of information");
}

uintb OpBehavior::recoverInputBinary(int32_t slot, int32_t sizeout, uintb out, int32_t sizein, uintb in) const {
    throw LowlevelError("Cannot recover input parameter without loss of information");
}

void OpBehavior::registerInstructions(std::vector<OpBehavior*>& inst, const Translate* trans) {
    inst.insert(inst.end(), CPUI_MAX, (OpBehavior*)0);

    inst[CPUI_COPY] = new OpBehaviorCopy();
    inst[CPUI_LOAD] = new OpBehavior(CPUI_LOAD, false, true);
    inst[CPUI_STORE] = new OpBehavior(CPUI_STORE, false, true);
    inst[CPUI_BRANCH] = new OpBehavior(CPUI_BRANCH, false, true);
    inst[CPUI_CBRANCH] = new OpBehavior(CPUI_CBRANCH, false, true);
    inst[CPUI_BRANCHIND] = new OpBehavior(CPUI_BRANCHIND, false, true);
    inst[CPUI_CALL] = new OpBehavior(CPUI_CALL, false, true);
    inst[CPUI_CALLIND] = new OpBehavior(CPUI_CALLIND, false, true);
    inst[CPUI_CALLOTHER] = new OpBehavior(CPUI_CALLOTHER, false, true);
    inst[CPUI_RETURN] = new OpBehavior(CPUI_RETURN, false, true);

    inst[CPUI_MULTIEQUAL] = new OpBehavior(CPUI_MULTIEQUAL, false, true);
    inst[CPUI_INDIRECT] = new OpBehavior(CPUI_INDIRECT, false, true);

    inst[CPUI_PIECE] = new OpBehaviorPiece();
    inst[CPUI_SUBPIECE] = new OpBehaviorSubpiece();
    inst[CPUI_INT_EQUAL] = new OpBehaviorEqual();
    inst[CPUI_INT_NOTEQUAL] = new OpBehaviorNotEqual();
    inst[CPUI_INT_SLESS] = new OpBehaviorIntSless();
    inst[CPUI_INT_SLESSEQUAL] = new OpBehaviorIntSlessEqual();
    inst[CPUI_INT_LESS] = new OpBehaviorIntLess();
    inst[CPUI_INT_LESSEQUAL] = new OpBehaviorIntLessEqual();
    inst[CPUI_INT_ZEXT] = new OpBehaviorIntZext();
    inst[CPUI_INT_SEXT] = new OpBehaviorIntSext();
    inst[CPUI_INT_ADD] = new OpBehaviorIntAdd();
    inst[CPUI_INT_SUB] = new OpBehaviorIntSub();
    inst[CPUI_INT_CARRY] = new OpBehaviorIntCarry();
    inst[CPUI_INT_SCARRY] = new OpBehaviorIntScarry();
    inst[CPUI_INT_SBORROW] = new OpBehaviorIntSborrow();
    inst[CPUI_INT_2COMP] = new OpBehaviorInt2Comp();
    inst[CPUI_INT_NEGATE] = new OpBehaviorIntNegate();
    inst[CPUI_INT_XOR] = new OpBehaviorIntXor();
    inst[CPUI_INT_AND] = new OpBehaviorIntAnd();
    inst[CPUI_INT_OR] = new OpBehaviorIntOr();
    inst[CPUI_INT_LEFT] = new OpBehaviorIntLeft();
    inst[CPUI_INT_RIGHT] = new OpBehaviorIntRight();
    inst[CPUI_INT_SRIGHT] = new OpBehaviorIntSright();
    inst[CPUI_INT_MULT] = new OpBehaviorIntMult();
    inst[CPUI_INT_DIV] = new OpBehaviorIntDiv();
    inst[CPUI_INT_SDIV] = new OpBehaviorIntSdiv();
    inst[CPUI_INT_REM] = new OpBehaviorIntRem();
    inst[CPUI_INT_SREM] = new OpBehaviorIntSrem();

    inst[CPUI_BOOL_NEGATE] = new OpBehaviorBoolNegate();
    inst[CPUI_BOOL_XOR] = new OpBehaviorBoolXor();
    inst[CPUI_BOOL_AND] = new OpBehaviorBoolAnd();
    inst[CPUI_BOOL_OR] = new OpBehaviorBoolOr();

    inst[CPUI_CAST] = new OpBehavior(CPUI_CAST, false, true);
    inst[CPUI_PTRADD] = new OpBehavior(CPUI_PTRADD, false);
    inst[CPUI_PTRSUB] = new OpBehavior(CPUI_PTRSUB, false);

    inst[CPUI_FLOAT_EQUAL] = new OpBehaviorFloatEqual(trans);
    inst[CPUI_FLOAT_NOTEQUAL] = new OpBehaviorFloatNotEqual(trans);
    inst[CPUI_FLOAT_LESS] = new OpBehaviorFloatLess(trans);
    inst[CPUI_FLOAT_LESSEQUAL] = new OpBehaviorFloatLessEqual(trans);
    inst[CPUI_FLOAT_NAN] = new OpBehaviorFloatNan(trans);
    inst[CPUI_FLOAT_ADD] = new OpBehaviorFloatAdd(trans);
    inst[CPUI_FLOAT_DIV] = new OpBehaviorFloatDiv(trans);
    inst[CPUI_FLOAT_MULT] = new OpBehaviorFloatMult(trans);
    inst[CPUI_FLOAT_SUB] = new OpBehaviorFloatSub(trans);
    inst[CPUI_FLOAT_NEG] = new OpBehaviorFloatNeg(trans);
    inst[CPUI_FLOAT_ABS] = new OpBehaviorFloatAbs(trans);
    inst[CPUI_FLOAT_SQRT] = new OpBehaviorFloatSqrt(trans);
    inst[CPUI_FLOAT_INT2FLOAT] = new OpBehaviorFloatInt2Float(trans);
    inst[CPUI_FLOAT_FLOAT2FLOAT] = new OpBehaviorFloatFloat2Float(trans);
    inst[CPUI_FLOAT_TRUNC] = new OpBehaviorFloatTrunc(trans);
    inst[CPUI_FLOAT_CEIL] = new OpBehaviorFloatCeil(trans);
    inst[CPUI_FLOAT_FLOOR] = new OpBehaviorFloatFloor(trans);
    inst[CPUI_FLOAT_ROUND] = new OpBehaviorFloatRound(trans);
    inst[CPUI_SEGMENTOP] = new OpBehavior(CPUI_SEGMENTOP, false, true);
    inst[CPUI_CPOOLREF] = new OpBehavior(CPUI_CPOOLREF, false, true);
    inst[CPUI_NEW] = new OpBehavior(CPUI_NEW, false, true);
    inst[CPUI_INSERT] = new OpBehavior(CPUI_INSERT, false);
    inst[CPUI_ZPULL] = new OpBehavior(CPUI_ZPULL, false);
    inst[CPUI_POPCOUNT] = new OpBehaviorPopcount();
    inst[CPUI_LZCOUNT] = new OpBehaviorLzcount();
    inst[CPUI_SPULL] = new OpBehavior(CPUI_SPULL, false);
}

uintb OpBehaviorCopy::evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const {
    return in1;
}

uintb OpBehaviorCopy::recoverInputUnary(int32_t sizeout, uintb out, int32_t sizein) const {
    return out;
}

uintb OpBehaviorEqual::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    return (in1 == in2) ? uintb(1) : uintb(0);
}

uintb OpBehaviorNotEqual::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    return (in1 != in2) ? uintb(1) : uintb(0);
}

uintb OpBehaviorIntSless::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    if (sizein <= 0) return 0;
    uintb sign_bit = uintb(1) << (sizein * 8 - 1);
    bool s1 = (in1 & sign_bit) != 0;
    bool s2 = (in2 & sign_bit) != 0;
    if (s1 != s2)
        return s1 ? uintb(1) : uintb(0);
    return (in1 < in2) ? uintb(1) : uintb(0);
}

uintb OpBehaviorIntSlessEqual::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    if (sizein <= 0) return 0;
    uintb sign_bit = uintb(1) << (sizein * 8 - 1);
    bool s1 = (in1 & sign_bit) != 0;
    bool s2 = (in2 & sign_bit) != 0;
    if (s1 != s2)
        return s1 ? uintb(1) : uintb(0);
    return (in1 <= in2) ? uintb(1) : uintb(0);
}

uintb OpBehaviorIntLess::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    return (in1 < in2) ? uintb(1) : uintb(0);
}

uintb OpBehaviorIntLessEqual::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    return (in1 <= in2) ? uintb(1) : uintb(0);
}

uintb OpBehaviorIntZext::evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const {
    return in1;
}

uintb OpBehaviorIntZext::recoverInputUnary(int32_t sizeout, uintb out, int32_t sizein) const {
    uintb mask = calc_mask(sizein);
    if ((mask & out) != out)
        throw EvaluationError("Output is not in range of zext operation");
    return out;
}

uintb OpBehaviorIntSext::evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const {
    return sign_extend(in1, sizein, sizeout);
}

uintb OpBehaviorIntSext::recoverInputUnary(int32_t sizeout, uintb out, int32_t sizein) const {
    uintb masklong = calc_mask(sizeout);
    uintb maskshort = calc_mask(sizein);
    uintb sign_bit = uintb(1) << (sizein * 8 - 1);
    if ((out & (sign_bit - 1)) == 0) {
        if ((out & maskshort) != out)
            throw EvaluationError("Output is not in range of sext operation");
    } else {
        if ((out & (masklong ^ maskshort)) != (masklong ^ maskshort))
            throw EvaluationError("Output is not in range of sext operation");
    }
    return (out & maskshort);
}

uintb OpBehaviorIntAdd::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    return (in1 + in2) & calc_mask(sizeout);
}

uintb OpBehaviorIntAdd::recoverInputBinary(int32_t slot, int32_t sizeout, uintb out, int32_t sizein, uintb in) const {
    return (out - in) & calc_mask(sizeout);
}

uintb OpBehaviorIntSub::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    return (in1 - in2) & calc_mask(sizeout);
}

uintb OpBehaviorIntSub::recoverInputBinary(int32_t slot, int32_t sizeout, uintb out, int32_t sizein, uintb in) const {
    uintb res;
    if (slot == 0)
        res = in + out;
    else
        res = in - out;
    return res & calc_mask(sizeout);
}

uintb OpBehaviorIntCarry::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    uintb sum = in1 + in2;
    uintb mask = calc_mask(sizein);
    return (sum > (sum & mask)) ? uintb(1) : uintb(0);
}

uintb OpBehaviorIntScarry::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    uintb res = in1 + in2;
    bool a = signbit_negative(in1, sizein);
    bool b = signbit_negative(in2, sizein);
    bool r = signbit_negative(res, sizein);
    return ((r ^ a) & (a ^ b ^ 1)) ? uintb(1) : uintb(0);
}

uintb OpBehaviorIntSborrow::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    uintb res = in1 - in2;
    bool a = signbit_negative(in1, sizein);
    bool b = signbit_negative(in2, sizein);
    bool r = signbit_negative(res, sizein);
    return ((a ^ r) & (r ^ b ^ 1)) ? uintb(1) : uintb(0);
}

uintb OpBehaviorInt2Comp::evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const {
    return uintb_negate(in1 - 1, sizein);
}

uintb OpBehaviorInt2Comp::recoverInputUnary(int32_t sizeout, uintb out, int32_t sizein) const {
    return uintb_negate(out - 1, sizein);
}

uintb OpBehaviorIntNegate::evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const {
    return uintb_negate(in1, sizein);
}

uintb OpBehaviorIntNegate::recoverInputUnary(int32_t sizeout, uintb out, int32_t sizein) const {
    return uintb_negate(out, sizein);
}

uintb OpBehaviorIntXor::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    return in1 ^ in2;
}

uintb OpBehaviorIntAnd::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    return in1 & in2;
}

uintb OpBehaviorIntOr::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    return in1 | in2;
}

uintb OpBehaviorIntLeft::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    if (in2 >= static_cast<uintb>(sizeout * 8)) return 0;
    int32_t sa = static_cast<int32_t>(in2);
    return (in1 << sa) & calc_mask(sizeout);
}

uintb OpBehaviorIntLeft::recoverInputBinary(int32_t slot, int32_t sizeout, uintb out, int32_t sizein, uintb in) const {
    if ((slot != 0) || (in >= static_cast<uintb>(sizeout * 8)))
        return OpBehavior::recoverInputBinary(slot, sizeout, out, sizein, in);
    int32_t sa = static_cast<int32_t>(in);
    if (((out << (8 * sizeout - sa)) & calc_mask(sizeout)) != 0)
        throw EvaluationError("Output is not in range of left shift operation");
    return out >> sa;
}

uintb OpBehaviorIntRight::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    if (in2 >= static_cast<uintb>(sizeout * 8)) return 0;
    int32_t sa = static_cast<int32_t>(in2);
    return (in1 & calc_mask(sizeout)) >> sa;
}

uintb OpBehaviorIntRight::recoverInputBinary(int32_t slot, int32_t sizeout, uintb out, int32_t sizein, uintb in) const {
    if ((slot != 0) || (in >= static_cast<uintb>(sizeout * 8)))
        return OpBehavior::recoverInputBinary(slot, sizeout, out, sizein, in);
    int32_t sa = static_cast<int32_t>(in);
    if ((out >> (8 * sizein - sa)) != 0)
        throw EvaluationError("Output is not in range of right shift operation");
    return out << sa;
}

uintb OpBehaviorIntSright::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    if (in2 >= static_cast<uintb>(8 * sizeout))
        return signbit_negative(in1, sizein) ? calc_mask(sizeout) : 0;
    int32_t sa = static_cast<int32_t>(in2);
    if (signbit_negative(in1, sizein)) {
        uintb res = in1 >> sa;
        uintb mask = calc_mask(sizein);
        mask = (mask >> sa) ^ mask;
        res |= mask;
        return res;
    } else {
        return in1 >> sa;
    }
}

uintb OpBehaviorIntSright::recoverInputBinary(int32_t slot, int32_t sizeout, uintb out, int32_t sizein, uintb in) const {
    if ((slot != 0) || (in >= static_cast<uintb>(sizeout * 8)))
        return OpBehavior::recoverInputBinary(slot, sizeout, out, sizein, in);
    int32_t sa = static_cast<int32_t>(in);
    uintb testval = out >> (sizein * 8 - sa - 1);
    int32_t count = 0;
    for (int32_t i = 0; i <= sa; ++i) {
        if ((testval & 1) != 0) count += 1;
        testval >>= 1;
    }
    if (count != sa + 1)
        throw EvaluationError("Output is not in range of right shift operation");
    return out << sa;
}

uintb OpBehaviorIntMult::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    return (in1 * in2) & calc_mask(sizeout);
}

uintb OpBehaviorIntDiv::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    if (in2 == 0) throw EvaluationError("Divide by 0");
    return in1 / in2;
}

uintb OpBehaviorIntSdiv::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    if (in2 == 0) throw EvaluationError("Divide by 0");
    int64_t num = sign_extend_signed(in1, 8 * sizein - 1);
    int64_t denom = sign_extend_signed(in2, 8 * sizein - 1);
    int64_t sres;
    if (denom == std::numeric_limits<int64_t>::min() && num == -1) {
        sres = std::numeric_limits<int64_t>::min();
    } else {
        sres = num / denom;
    }
    return static_cast<uintb>(static_cast<uint64_t>(sres)) & calc_mask(sizeout);
}

uintb OpBehaviorIntRem::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    if (in2 == 0) throw EvaluationError("Remainder by 0");
    return in1 % in2;
}

uintb OpBehaviorIntSrem::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    if (in2 == 0) throw EvaluationError("Remainder by 0");
    int64_t val = sign_extend_signed(in1, 8 * sizein - 1);
    int64_t mod = sign_extend_signed(in2, 8 * sizein - 1);
    int64_t sres = val % mod;
    return static_cast<uintb>(static_cast<uint64_t>(sres)) & calc_mask(sizeout);
}

uintb OpBehaviorBoolNegate::evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const {
    return in1 ^ 1;
}

uintb OpBehaviorBoolXor::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    return in1 ^ in2;
}

uintb OpBehaviorBoolAnd::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    return in1 & in2;
}

uintb OpBehaviorBoolOr::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    return in1 | in2;
}

uintb OpBehaviorFloatEqual::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    const FloatFormat* format = translate->getFloatFormat(sizein);
    if (format == nullptr)
        return OpBehavior::evaluateBinary(sizeout, sizein, in1, in2);
    return format->opEqual(static_cast<uint64_t>(in1), static_cast<uint64_t>(in2));
}

#define FF_CALL1(name, fn) \
    const FloatFormat* format = translate->getFloatFormat(sizein); \
    if (format == nullptr) return OpBehavior::evaluateUnary(sizeout, sizein, in1); \
    return format->fn(static_cast<uint64_t>(in1))

#define FF_CALL2(name, fn) \
    const FloatFormat* format = translate->getFloatFormat(sizein); \
    if (format == nullptr) return OpBehavior::evaluateBinary(sizeout, sizein, in1, in2); \
    return format->fn(static_cast<uint64_t>(in1), static_cast<uint64_t>(in2))

uintb OpBehaviorFloatNotEqual::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    FF_CALL2(OpBehaviorFloatNotEqual, opNotEqual);
}

uintb OpBehaviorFloatLess::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    FF_CALL2(OpBehaviorFloatLess, opLess);
}

uintb OpBehaviorFloatLessEqual::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    FF_CALL2(OpBehaviorFloatLessEqual, opLessEqual);
}

uintb OpBehaviorFloatNan::evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const {
    FF_CALL1(OpBehaviorFloatNan, opNan);
}

uintb OpBehaviorFloatAdd::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    FF_CALL2(OpBehaviorFloatAdd, opAdd);
}

uintb OpBehaviorFloatDiv::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    FF_CALL2(OpBehaviorFloatDiv, opDiv);
}

uintb OpBehaviorFloatMult::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    FF_CALL2(OpBehaviorFloatMult, opMult);
}

uintb OpBehaviorFloatSub::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    FF_CALL2(OpBehaviorFloatSub, opSub);
}

uintb OpBehaviorFloatNeg::evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const {
    FF_CALL1(OpBehaviorFloatNeg, opNeg);
}

uintb OpBehaviorFloatAbs::evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const {
    FF_CALL1(OpBehaviorFloatAbs, opAbs);
}

uintb OpBehaviorFloatSqrt::evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const {
    FF_CALL1(OpBehaviorFloatSqrt, opSqrt);
}

uintb OpBehaviorFloatInt2Float::evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const {
    return translate->getFloatFormat(sizein)->opInt2Float(static_cast<uint64_t>(in1), sizein);
}

uintb OpBehaviorFloatFloat2Float::evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const {
    const FloatFormat* fmt = translate->getFloatFormat(sizein);
    const FloatFormat* outfmt = translate->getFloatFormat(sizeout);
    if (fmt == nullptr || outfmt == nullptr)
        return OpBehavior::evaluateUnary(sizeout, sizein, in1);
    return fmt->opFloat2Float(static_cast<uint64_t>(in1), *outfmt);
}

uintb OpBehaviorFloatTrunc::evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const {
    return translate->getFloatFormat(sizein)->opTrunc(static_cast<uint64_t>(in1), sizeout);
}

uintb OpBehaviorFloatCeil::evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const {
    FF_CALL1(OpBehaviorFloatCeil, opCeil);
}

uintb OpBehaviorFloatFloor::evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const {
    FF_CALL1(OpBehaviorFloatFloor, opFloor);
}

uintb OpBehaviorFloatRound::evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const {
    FF_CALL1(OpBehaviorFloatRound, opRound);
}

#undef FF_CALL1
#undef FF_CALL2

uintb OpBehaviorPiece::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    return (in1 << ((sizeout - sizein) * 8)) | in2;
}

uintb OpBehaviorSubpiece::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    int32_t sa = static_cast<int32_t>(in2) * 8;
    return (in1 >> sa) & calc_mask(sizeout);
}

uintb OpBehaviorPtradd::evaluateTernary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2, uintb in3) const {
    return (in1 + in2 * in3) & calc_mask(sizeout);
}

uintb OpBehaviorPtrsub::evaluateBinary(int32_t sizeout, int32_t sizein, uintb in1, uintb in2) const {
    return (in1 + in2) & calc_mask(sizeout);
}

uintb OpBehaviorPopcount::evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const {
    return uintb(popcount(in1));
}

uintb OpBehaviorLzcount::evaluateUnary(int32_t sizeout, int32_t sizein, uintb in1) const {
    if (in1 == 0) return uintb(sizein * 8);
    int32_t msbidx = static_cast<int32_t>(msb(in1));
    return uintb(sizein * 8 - msbidx - 1);
}

} // namespace ghidra
