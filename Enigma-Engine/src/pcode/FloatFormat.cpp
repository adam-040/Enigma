/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 * NOTE: uses some windows and sparc specific floating point definitions
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file FloatFormat.cpp
/// \brief Implementation of IEEE 754 floating-point encoding/decoding
#include "ghidra/FloatFormat.h"

#include <cmath>
#include <limits>
#include <sstream>

namespace ghidra {

using std::ldexp;
using std::frexp;
using std::signbit;
using std::sqrt;
using std::floor;
using std::ceil;
using std::round;
using std::fabs;

// --- Local helper functions (from address.hh equivalents) ---

static inline uint64_t calc_mask(int32_t size) {
  if (size >= 8) return ~(uint64_t)0;
  if (size <= 0) return 0;
  return ((uint64_t)1 << (size * 8)) - 1;
}

static inline uint64_t sign_extend(uint64_t in, int32_t bit) {
  if (bit >= 63) return in;
  uint64_t mask = (uint64_t)1 << bit;
  uint64_t res = in & ((mask << 1) - 1);
  if (res & mask)
    res |= ~((mask << 1) - 1);
  return res;
}

// Count leading zeros in a uint64_t value
static inline int32_t count_leading_zeros(uint64_t val) {
  if (val == 0) return 64;
  int32_t n = 0;
  if ((val >> 32) == 0) { n += 32; val <<= 32; }
  if ((val >> 48) == 0) { n += 16; val <<= 16; }
  if ((val >> 56) == 0) { n += 8; val <<= 8; }
  if ((val >> 60) == 0) { n += 4; val <<= 4; }
  if ((val >> 62) == 0) { n += 2; val <<= 2; }
  if ((val >> 63) == 0) { n += 1; }
  return n;
}

/// Set format for a given encoding size according to IEEE 754 standards
/// \param sz is the size of the encoding in bytes
FloatFormat::FloatFormat(int32_t sz)
{
  size = sz;

  if (size == 4) {
    signbit_pos = 31;
    exp_pos = 23;
    exp_size = 8;
    frac_pos = 0;
    frac_size = 23;
    bias = 127;
    jbitimplied = true;
  }
  else if (size == 8) {
    signbit_pos = 63;
    exp_pos = 52;
    exp_size = 11;
    frac_pos = 0;
    frac_size = 52;
    bias = 1023;
    jbitimplied = true;
  }
  maxexponent = (1 << exp_size) - 1;
  calcPrecision();
}

/// \param sign is set to \b true if the value should be negative
/// \param signif is the fractional part
/// \param exp is the exponent
/// \return the constructed floating-point value
double FloatFormat::createFloat(bool sign, uint64_t signif, int32_t exp)
{
  signif >>= 1;               // Throw away 1 bit of precision we will
                              // lose anyway, to make sure highbit is 0
  int32_t precis = 8 * sizeof(uint64_t) - 1;  // fullword - 1 we threw away
  double res = (double)signif;
  int32_t expchange = exp - precis + 1;  // change in exponent is precis
                              // -1 integer bit
  res = ldexp(res, expchange);
  if (sign)
    res = res * -1.0;
  return res;
}

/// \brief Extract the sign, fractional, and exponent from a given floating-point value
///
/// \param x is the given value
/// \param sgn passes back the sign
/// \param signif passes back the fractional part
/// \param exp passes back the exponent
/// \return the floating-point class of the value
FloatFormat::floatclass FloatFormat::extractExpSig(double x, bool* sgn, uint64_t* signif, int32_t* exp)
{
  int32_t e;

  *sgn = signbit(x);
  if (x == 0.0) return zero;
  if (std::isinf(x)) return infinity;
  if (std::isnan(x)) return nan;
  if (*sgn)
    x = -x;
  double norm = frexp(x, &e);  // norm is between 1/2 and 1
  norm = ldexp(norm, 8 * sizeof(uint64_t) - 1);  // norm between 2^62 and 2^63

  *signif = (uint64_t)norm;    // Convert to normalized integer
  *signif <<= 1;

  e -= 1;    // Consider normalization between 1 and 2
  *exp = e;
  return normalized;
}

/// \param x is an encoded floating-point value
/// \return the fraction part of the value aligned to the top of the word
uint64_t FloatFormat::extractFractionalCode(uint64_t x) const
{
  x >>= frac_pos;              // Eliminate bits below
  x <<= 8 * sizeof(uint64_t) - frac_size;  // Align with top of word
  return x;
}

/// \param x is an encoded floating-point value
/// \return the sign bit
bool FloatFormat::extractSign(uint64_t x) const
{
  x >>= signbit_pos;
  return ((x & 1) != 0);
}

/// \param x is an encoded floating-point value
/// \return the (signed) exponent
int32_t FloatFormat::extractExponentCode(uint64_t x) const
{
  x >>= exp_pos;
  uint64_t mask = 1;
  mask = (mask << exp_size) - 1;
  return (int32_t)(x & mask);
}

/// \param x is an encoded value (with fraction part set to zero)
/// \param code is the new fractional value to set
/// \return the encoded value with the fractional filled in
uint64_t FloatFormat::setFractionalCode(uint64_t x, uint64_t code) const
{
  // Align with bottom of word, also drops bits of precision
  // we don't have room for
  code >>= 8 * sizeof(uint64_t) - frac_size;
  code <<= frac_pos;           // Move bits into position;
  x |= code;
  return x;
}

/// \param x is an encoded value (with sign set to zero)
/// \param sign is the sign bit to set
/// \return the encoded value with the sign bit set
uint64_t FloatFormat::setSign(uint64_t x, bool sign) const
{
  if (!sign) return x;         // Assume bit is already zero
  uint64_t mask = 1;
  mask <<= signbit_pos;
  x |= mask;                   // Stick in the bit
  return x;
}

/// \param x is an encoded value (with exponent set to zero)
/// \param code is the exponent to set
/// \return the encoded value with the new exponent
uint64_t FloatFormat::setExponentCode(uint64_t x, uint64_t code) const
{
  code <<= exp_pos;            // Move bits into position
  x |= code;
  return x;
}

/// \param sgn is set to \b true for negative zero, \b false for positive
/// \return the encoded zero
uint64_t FloatFormat::getZeroEncoding(bool sgn) const
{
  uint64_t res = 0;
  // Use IEEE 754 standard for zero encoding
  res = setFractionalCode(res, 0);
  res = setExponentCode(res, 0);
  return setSign(res, sgn);
}

/// \param sgn is set to \b true for negative infinity, \b false for positive
/// \return the encoded infinity
uint64_t FloatFormat::getInfinityEncoding(bool sgn) const
{
  uint64_t res = 0;
  // Use IEEE 754 standard for infinity encoding
  res = setFractionalCode(res, 0);
  res = setExponentCode(res, (uint64_t)maxexponent);
  return setSign(res, sgn);
}

/// \param sgn is set to \b true for negative NaN, \b false for positive
/// \return the encoded NaN
uint64_t FloatFormat::getNaNEncoding(bool sgn) const
{
  uint64_t res = 0;
  // Use IEEE 754 standard for NaN encoding
  uint64_t mask = 1;
  mask <<= 8 * sizeof(uint64_t) - 1;  // Create "quiet" NaN
  res = setFractionalCode(res, mask);
  res = setExponentCode(res, (uint64_t)maxexponent);
  return setSign(res, sgn);
}

void FloatFormat::calcPrecision()
{
  decimalMinPrecision = (int32_t)floor(frac_size * 0.30103);
  // Precision needed to guarantee IEEE 754 binary -> decimal -> binary round trip conversion
  decimalMaxPrecision = (int32_t)ceil((frac_size + 1) * 0.30103) + 1;
}

/// \param encoding is the encoded floating-point value
/// \return either \e zero, \e infinity, \e denormalized, \e nan, or \e normalized
FloatFormat::floatclass FloatFormat::getClass(uint64_t encoding) const
{
  int32_t exp = extractExponentCode(encoding);
  if (exp == 0) {
    if (extractFractionalCode(encoding) == 0)
      return zero;
    return denormalized;
  }
  if (exp == maxexponent) {
    if (extractFractionalCode(encoding) == 0)
      return infinity;
    return nan;
  }
  return normalized;
}

/// \param encoding is the encoding value
/// \param type points to the floating-point class, which is passed back
/// \return the equivalent double value
double FloatFormat::getHostFloat(uint64_t encoding, floatclass* type) const
{
  bool sgn = extractSign(encoding);
  uint64_t frac = extractFractionalCode(encoding);
  int32_t exp = extractExponentCode(encoding);
  bool normal = true;

  if (exp == 0) {
    if (frac == 0) {           // Floating point zero
      *type = zero;
      return sgn ? -0.0 : +0.0;
    }
    *type = denormalized;
    // Number is denormalized
    normal = false;
  }
  else if (exp == maxexponent) {
    if (frac == 0) {           // Floating point infinity
      *type = infinity;
      double infinity = std::numeric_limits<double>::infinity();
      return sgn ? -infinity : +infinity;
    }
    *type = nan;
    // encoding is "Not a Number" NaN
    double nan = std::numeric_limits<double>::quiet_NaN();
    return sgn ? -nan : +nan;  // Sign is usually ignored
  }
  else
    *type = normalized;

  // Get "true" exponent and fractional
  exp -= bias;
  if (normal && jbitimplied) {
    frac >>= 1;                // Make room for 1 jbit
    uint64_t highbit = 1;
    highbit <<= 8 * sizeof(uint64_t) - 1;
    frac |= highbit;           // Stick bit in at top
  }
  return createFloat(sgn, frac, exp);
}

/// \brief Round a floating point value to the nearest even
///
/// \param signif the significant bits of a floating point value
/// \param lowbitpos the position in signif of the floating point
/// \return true if we rounded up
bool FloatFormat::roundToNearestEven(uint64_t& signif, int32_t lowbitpos)
{
  uint64_t lowbitmask = (lowbitpos < 8 * sizeof(uint64_t)) ? ((uint64_t)1 << lowbitpos) : 0;
  uint64_t midbitmask = (uint64_t)1 << (lowbitpos - 1);
  uint64_t epsmask = midbitmask - 1;
  bool odd = (signif & lowbitmask) != 0;
  if ((signif & midbitmask) != 0 && ((signif & epsmask) != 0 || odd)) {
    signif += midbitmask;
    return true;
  }
  return false;
}

/// \param host is the double value to convert
/// \return the equivalent encoded value
uint64_t FloatFormat::getEncoding(double host) const
{
  floatclass type;
  bool sgn;
  uint64_t signif;
  int32_t exp;

  type = extractExpSig(host, &sgn, &signif, &exp);
  if (type == zero)
    return getZeroEncoding(sgn);
  else if (type == infinity)
    return getInfinityEncoding(sgn);
  else if (type == nan)
    return getNaNEncoding(sgn);

  // convert exponent and fractional to their encodings
  exp += bias;

  if (exp < -frac_size) {       // Exponent is too small to represent
    // Round-to-nearest-even: flush to zero if significand is zero or below
    // half of the smallest subnormal; otherwise return smallest subnormal
    if (signif == 0) return getZeroEncoding(sgn);
    int shift = -exp - frac_size - 1;
    if (shift <= 0) return getZeroEncoding(sgn);
    uint64_t roundBit = (signif >> (shift - 1)) & 1;
    uint64_t sticky = signif & ((1ULL << (shift - 1)) - 1);
    if (roundBit == 0) return getZeroEncoding(sgn);
    if (sticky == 0 && (signif >> shift) % 2 == 0) return getZeroEncoding(sgn);
    // Round up to smallest subnormal
    uint64_t res = getZeroEncoding(sgn);
    return setFractionalCode(res, (uint64_t)1 << (frac_size - 1));
  }

  if (exp < 1) {               // Must be denormalized
    if (roundToNearestEven(signif, 8 * sizeof(uint64_t) - frac_size - exp)) {
      if ((signif >> (8 * sizeof(uint64_t) - 1)) == 0) {
        signif = (uint64_t)1 << (8 * sizeof(uint64_t) - 1);
        exp += 1;
      }
    }
    if (exp >= 1) {
      // Rounded up from denormalized to normal range: encode as normal
      goto encode_normal;
    }
    uint64_t res = getZeroEncoding(sgn);
    return setFractionalCode(res, signif >> (-exp));
  }

encode_normal:
  if (roundToNearestEven(signif, 8 * sizeof(uint64_t) - frac_size - 1)) {
    // if high bit is clear, then the add overflowed. Increase exp and set
    // signif to 1.
    if ((signif >> (8 * sizeof(uint64_t) - 1)) == 0) {
      signif = (uint64_t)1 << (8 * sizeof(uint64_t) - 1);
      exp += 1;
    }
  }

  if (exp >= maxexponent)      // Exponent is too big to represent
    return getInfinityEncoding(sgn);

  if (jbitimplied && (exp != 0))
    signif <<= 1;              // Cut off top bit (which should be 1)

  uint64_t res = 0;
  res = setFractionalCode(res, signif);
  res = setExponentCode(res, (uint64_t)exp);
  return setSign(res, sgn);
}

/// \param encoding is the value in the \e other FloatFormat
/// \param formin is the \e other FloatFormat
/// \return the equivalent value in \b this FloatFormat
uint64_t FloatFormat::convertEncoding(uint64_t encoding,
    const FloatFormat* formin) const
{
  bool sgn = formin->extractSign(encoding);
  uint64_t signif = formin->extractFractionalCode(encoding);
  int32_t exp = formin->extractExponentCode(encoding);

  if (exp == formin->maxexponent) {  // NaN or INFINITY encoding
    exp = maxexponent;
    if (signif != 0)
      return getNaNEncoding(sgn);
    else
      return getInfinityEncoding(sgn);
  }

  if (exp == 0) {              // incoming is subnormal
    if (signif == 0)
      return getZeroEncoding(sgn);

    // normalize
    int32_t lz = count_leading_zeros(signif);
    signif <<= lz;
    exp = -formin->bias - lz;
  }
  else {                       // incoming is normal
    exp -= formin->bias;
    if (jbitimplied)
      signif = ((uint64_t)1 << (8 * sizeof(uint64_t) - 1)) | (signif >> 1);
  }

  exp += bias;

  if (exp < -frac_size) {       // Exponent is too small to represent
    // Round-to-nearest-even: flush to zero if significand is zero or below
    // half of the smallest subnormal; otherwise return smallest subnormal
    if (signif == 0) return getZeroEncoding(sgn);
    int shift = -exp - frac_size - 1;
    if (shift <= 0) return getZeroEncoding(sgn);
    uint64_t roundBit = (signif >> (shift - 1)) & 1;
    uint64_t sticky = signif & ((1ULL << (shift - 1)) - 1);
    if (roundBit == 0) return getZeroEncoding(sgn);
    if (sticky == 0 && (signif >> shift) % 2 == 0) return getZeroEncoding(sgn);
    uint64_t res = getZeroEncoding(sgn);
    return setFractionalCode(res, (uint64_t)1 << (frac_size - 1));
  }

  if (exp < 1) {               // Must be denormalized
    if (roundToNearestEven(signif, 8 * sizeof(uint64_t) - frac_size - exp)) {
      if ((signif >> (8 * sizeof(uint64_t) - 1)) == 0) {
        signif = (uint64_t)1 << (8 * sizeof(uint64_t) - 1);
        exp += 1;
      }
    }
    if (exp >= 1)
      goto convert_encode_normal;
    uint64_t res = getZeroEncoding(sgn);
    return setFractionalCode(res, signif >> (-exp));
  }

convert_encode_normal:
  if (roundToNearestEven(signif, 8 * sizeof(uint64_t) - frac_size - 1)) {
    // if high bit is clear, then the add overflowed. Increase exp and set
    // signif to 1.
    if ((signif >> (8 * sizeof(uint64_t) - 1)) == 0) {
      signif = (uint64_t)1 << (8 * sizeof(uint64_t) - 1);
      exp += 1;
    }
  }

  if (exp >= maxexponent)      // Exponent is too big to represent
    return getInfinityEncoding(sgn);

  if (jbitimplied && (exp != 0))
    signif <<= 1;              // Cut off top bit (which should be 1)

  uint64_t res = 0;
  res = setFractionalCode(res, signif);
  res = setExponentCode(res, (uint64_t)exp);
  return setSign(res, sgn);
}

/// The string should be printed with the minimum number of digits to uniquely specify the underlying
/// binary value.
/// If the \b forcesci parameter is \b true, the string will always be printed using scientific notation.
/// \param host is the given value already converted to the host's \b double format.
/// \param forcesci is \b true if the value should be printed in scientific notation.
/// \return the decimal representation as a string
std::string FloatFormat::printDecimal(double host, bool forcesci) const
{
  std::string res;
  for (int32_t prec = decimalMinPrecision;; ++prec) {
    std::ostringstream s;
    if (forcesci) {
      s.setf(std::ios::scientific);
      s.precision(prec - 1);
    }
    else {
      s.unsetf(std::ios::floatfield);
      s.precision(prec);
    }
    s << host;
    if (prec == decimalMaxPrecision) {
      return s.str();
    }
    res = s.str();
    double roundtrip = 0.0;
    std::istringstream t(res);
    if (size <= 4) {
      float tmp = 0.0f;
      t >> tmp;
      roundtrip = tmp;
    }
    else {
      t >> roundtrip;
    }
    if (roundtrip == host)
      break;
  }
  return res;
}

// Currently we emulate floating point operations on the target
// By converting the encoding to the host's encoding and then
// performing the operation using the host's floating point unit
// then the host's encoding is converted back to the targets encoding

/// \param a is the first floating-point value
/// \param b is the second floating-point value
/// \return \b true if (a == b)
uint64_t FloatFormat::opEqual(uint64_t a, uint64_t b) const
{
  floatclass type;
  double val1 = getHostFloat(a, &type);
  double val2 = getHostFloat(b, &type);
  uint64_t res = (val1 == val2) ? 1 : 0;
  return res;
}

/// \param a is the first floating-point value
/// \param b is the second floating-point value
/// \return \b true if (a != b)
uint64_t FloatFormat::opNotEqual(uint64_t a, uint64_t b) const
{
  floatclass type;
  double val1 = getHostFloat(a, &type);
  double val2 = getHostFloat(b, &type);
  uint64_t res = (val1 != val2) ? 1 : 0;
  return res;
}

/// \param a is the first floating-point value
/// \param b is the second floating-point value
/// \return \b true if (a < b)
uint64_t FloatFormat::opLess(uint64_t a, uint64_t b) const
{
  floatclass type;
  double val1 = getHostFloat(a, &type);
  double val2 = getHostFloat(b, &type);
  uint64_t res = (val1 < val2) ? 1 : 0;
  return res;
}

/// \param a is the first floating-point value
/// \param b is the second floating-point value
/// \return \b true if (a <= b)
uint64_t FloatFormat::opLessEqual(uint64_t a, uint64_t b) const
{
  floatclass type;
  double val1 = getHostFloat(a, &type);
  double val2 = getHostFloat(b, &type);
  uint64_t res = (val1 <= val2) ? 1 : 0;
  return res;
}

/// \param a is an encoded floating-point value
/// \return \b true if a is Not-a-Number
uint64_t FloatFormat::opNan(uint64_t a) const
{
  floatclass type;
  getHostFloat(a, &type);
  uint64_t res = (type == FloatFormat::nan) ? 1 : 0;
  return res;
}

/// \param a is the first floating-point value
/// \param b is the second floating-point value
/// \return a + b
uint64_t FloatFormat::opAdd(uint64_t a, uint64_t b) const
{
  floatclass type;
  double val1 = getHostFloat(a, &type);
  double val2 = getHostFloat(b, &type);
  return getEncoding(val1 + val2);
}

/// \param a is the first floating-point value
/// \param b is the second floating-point value
/// \return a / b
uint64_t FloatFormat::opDiv(uint64_t a, uint64_t b) const
{
  floatclass type;
  double val1 = getHostFloat(a, &type);
  double val2 = getHostFloat(b, &type);
  return getEncoding(val1 / val2);
}

/// \param a is the first floating-point value
/// \param b is the second floating-point value
/// \return a * b
uint64_t FloatFormat::opMult(uint64_t a, uint64_t b) const
{
  floatclass type;
  double val1 = getHostFloat(a, &type);
  double val2 = getHostFloat(b, &type);
  return getEncoding(val1 * val2);
}

/// \param a is the first floating-point value
/// \param b is the second floating-point value
/// \return a - b
uint64_t FloatFormat::opSub(uint64_t a, uint64_t b) const
{
  floatclass type;
  double val1 = getHostFloat(a, &type);
  double val2 = getHostFloat(b, &type);
  return getEncoding(val1 - val2);
}

/// \param a is an encoded floating-point value
/// \return -a
uint64_t FloatFormat::opNeg(uint64_t a) const
{
  floatclass type;
  double val = getHostFloat(a, &type);
  return getEncoding(-val);
}

/// \param a is an encoded floating-point value
/// \return abs(a)
uint64_t FloatFormat::opAbs(uint64_t a) const
{
  floatclass type;
  double val = getHostFloat(a, &type);
  return getEncoding(fabs(val));
}

/// \param a is an encoded floating-point value
/// \return sqrt(a)
uint64_t FloatFormat::opSqrt(uint64_t a) const
{
  floatclass type;
  double val = getHostFloat(a, &type);
  return getEncoding(sqrt(val));
}

/// \param a is a signed integer value
/// \param sizein is the number of bytes in the integer encoding
/// \return a converted to an encoded floating-point value
uint64_t FloatFormat::opInt2Float(uint64_t a, int32_t sizein) const
{
  int64_t ival = (int64_t)sign_extend(a, 8 * sizein - 1);
  double val = (double)ival;   // Convert integer to float
  return getEncoding(val);
}

/// \param a is an encoded floating-point value
/// \param outformat is the desired output FloatFormat
/// \return a converted to the output FloatFormat
uint64_t FloatFormat::opFloat2Float(uint64_t a, const FloatFormat& outformat) const
{
  return outformat.convertEncoding(a, this);
}

/// \param a is an encoded floating-point value
/// \param sizeout is the desired encoding size of the output
/// \return an integer encoding of a
uint64_t FloatFormat::opTrunc(uint64_t a, int32_t sizeout) const
{
  floatclass type;
  double val = getHostFloat(a, &type);
  int64_t ival = (int64_t)val;   // Convert to integer
  uint64_t res = (uint64_t)ival; // Convert to unsigned
  res &= calc_mask(sizeout);     // Truncate to proper size
  return res;
}

/// \param a is an encoded floating-point value
/// \return ceil(a)
uint64_t FloatFormat::opCeil(uint64_t a) const
{
  floatclass type;
  double val = getHostFloat(a, &type);
  return getEncoding(ceil(val));
}

/// \param a is an encoded floating-point value
/// \return floor(a)
uint64_t FloatFormat::opFloor(uint64_t a) const
{
  floatclass type;
  double val = getHostFloat(a, &type);
  return getEncoding(floor(val));
}

/// \param a is an encoded floating-point value
/// \return round(a)
uint64_t FloatFormat::opRound(uint64_t a) const
{
  floatclass type;
  double val = getHostFloat(a, &type);
  return getEncoding(round(val));
}

} // namespace ghidra
