/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file FloatFormat.h
/// \brief Support for decoding different floating-point formats
#pragma once

#include "LowlevelError.h"
#include <cstdint>
#include <string>

namespace ghidra {

/// \brief Encoding information for a single floating-point format
///
/// This class supports manipulation of a single floating-point encoding.
/// An encoding can be converted to and from the host format and
/// convenience methods allow p-code floating-point operations to be
/// performed on natively encoded operands.  This follows the IEEE754 standards.
class FloatFormat {
public:
  /// \brief The various classes of floating-point encodings
  enum floatclass {
    normalized = 0,      ///< A normal floating-point number
    infinity = 1,        ///< An encoding representing an infinite value
    zero = 2,            ///< An encoding of the value zero
    nan = 3,             ///< An invalid encoding, Not-a-Number
    denormalized = 4     ///< A denormalized encoding (for very small values)
  };
private:
  int32_t size;           ///< Size of float in bytes (this format)
  int32_t signbit_pos;    ///< Bit position of sign bit
  int32_t frac_pos;       ///< (lowest) bit position of fractional part
  int32_t frac_size;      ///< Number of bits in fractional part
  int32_t exp_pos;        ///< (lowest) bit position of exponent
  int32_t exp_size;       ///< Number of bits in exponent
  int32_t bias;           ///< What to add to real exponent to get encoding
  int32_t maxexponent;    ///< Maximum possible exponent
  int32_t decimalMinPrecision;  ///< Minimum decimal digits of precision guaranteed by the format
  int32_t decimalMaxPrecision;  ///< Maximum decimal digits of precision needed to uniquely represent value
  bool jbitimplied;       ///< Set to \b true if integer bit of 1 is assumed
  static double createFloat(bool sign, uint64_t signif, int32_t exp);
  static floatclass extractExpSig(double x, bool* sgn, uint64_t* signif, int32_t* exp);
  static bool roundToNearestEven(uint64_t& signif, int32_t lowbitpos);
  uint64_t setFractionalCode(uint64_t x, uint64_t code) const;
  uint64_t setSign(uint64_t x, bool sign) const;
  uint64_t setExponentCode(uint64_t x, uint64_t code) const;
  void calcPrecision();
public:
  explicit FloatFormat(int32_t sz);
  int32_t getSize() const { return size; }
  floatclass getClass(uint64_t encoding) const;
  double getHostFloat(uint64_t encoding, floatclass* type) const;
  uint64_t getEncoding(double host) const;
  uint64_t convertEncoding(uint64_t encoding, const FloatFormat* formin) const;

  uint64_t extractFractionalCode(uint64_t x) const;
  bool extractSign(uint64_t x) const;
  int32_t extractExponentCode(uint64_t x) const;
  int32_t getExponent(uint64_t x) const { return extractExponentCode(x) - bias; }

  uint64_t getZeroEncoding(bool sgn) const;
  uint64_t getInfinityEncoding(bool sgn) const;
  uint64_t getNaNEncoding(bool sgn) const;

  std::string printDecimal(double host, bool forcesci) const;

  uint64_t opEqual(uint64_t a, uint64_t b) const;
  uint64_t opNotEqual(uint64_t a, uint64_t b) const;
  uint64_t opLess(uint64_t a, uint64_t b) const;
  uint64_t opLessEqual(uint64_t a, uint64_t b) const;
  uint64_t opNan(uint64_t a) const;
  uint64_t opAdd(uint64_t a, uint64_t b) const;
  uint64_t opDiv(uint64_t a, uint64_t b) const;
  uint64_t opMult(uint64_t a, uint64_t b) const;
  uint64_t opSub(uint64_t a, uint64_t b) const;
  uint64_t opNeg(uint64_t a) const;
  uint64_t opAbs(uint64_t a) const;
  uint64_t opSqrt(uint64_t a) const;
  uint64_t opTrunc(uint64_t a, int32_t sizeout) const;
  uint64_t opCeil(uint64_t a) const;
  uint64_t opFloor(uint64_t a) const;
  uint64_t opRound(uint64_t a) const;
  uint64_t opInt2Float(uint64_t a, int32_t sizein) const;
  uint64_t opFloat2Float(uint64_t a, const FloatFormat& outformat) const;
};

} // namespace ghidra
