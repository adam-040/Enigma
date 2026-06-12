/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file MaskImpl.cpp
#include "ghidra/MaskImpl.h"
#include "ghidra/MemoryAccessException.h"
#include "ghidra/IncompatibleMaskException.h"
#include <stdexcept>
#include <sstream>
#include <iomanip>

namespace ghidra {

MaskImpl::MaskImpl(const std::vector<uint8_t>& msk) {
    if (msk.empty()) throw std::invalid_argument("MaskImpl: null mask");
    mask = msk;
}

MaskImpl::MaskImpl(const uint8_t* msk, size_t len) {
    if (msk == nullptr || len == 0) throw std::invalid_argument("MaskImpl: null mask");
    mask.assign(msk, msk + len);
}

bool MaskImpl::equals(const Mask* obj) const {
    if (obj == nullptr) return false;
    return equals(obj->getBytes());
}

bool MaskImpl::equals(const std::vector<uint8_t>& otherMask) const {
    if (otherMask.size() != mask.size()) return false;
    for (size_t i = 0; i < mask.size(); ++i) {
        if (mask[i] != otherMask[i]) return false;
    }
    return true;
}

std::vector<uint8_t> MaskImpl::applyMask(const std::vector<uint8_t>& cde, std::vector<uint8_t>& result) {
    if (result.size() < cde.size()) throw IncompatibleMaskException("MaskImpl::applyMask: result too small");
    for (size_t i = 0; i < mask.size() && i < cde.size(); ++i) {
        result[i] = (uint8_t)(mask[i] & cde[i]);
    }
    for (size_t i = mask.size(); i < cde.size(); ++i) {
        result[i] = cde[i];
    }
    return result;
}

void MaskImpl::applyMask(const std::vector<uint8_t>& cde, int cdeOffset,
                         std::vector<uint8_t>& results, int resultsOffset) {
    if ((int)cde.size() - cdeOffset < (int)mask.size() ||
        (int)results.size() - resultsOffset < (int)mask.size()) {
        throw IncompatibleMaskException("MaskImpl::applyMask (offset): buffer too small");
    }
    for (size_t i = 0; i < mask.size(); ++i) {
        results[resultsOffset++] = (uint8_t)(mask[i] & cde[cdeOffset++]);
    }
}

std::vector<uint8_t> MaskImpl::applyMask(MemBuffer* buffer) {
    if (buffer == nullptr) throw MemoryAccessException("MaskImpl::applyMask: null buffer");
    std::vector<uint8_t> bytes(mask.size());
    buffer->getBytes(bytes, 0);
    for (size_t i = 0; i < mask.size() && i < bytes.size(); ++i) {
        bytes[i] = (uint8_t)(bytes[i] & mask[i]);
    }
    return bytes;
}

bool MaskImpl::equalMaskedValue(const std::vector<uint8_t>& cde, const std::vector<uint8_t>& target) {
    if (cde.size() < mask.size() || target.size() < mask.size()) {
        throw IncompatibleMaskException("MaskImpl::equalMaskedValue: buffer too small");
    }
    for (size_t i = 0; i < mask.size(); ++i) {
        if (target[i] != (uint8_t)(mask[i] & cde[i])) return false;
    }
    return true;
}

bool MaskImpl::subMask(const std::vector<uint8_t>& msk) {
    if (mask.size() < msk.size()) return false;
    for (size_t i = 0; i < msk.size(); ++i) {
        uint8_t b = (uint8_t)(mask[i] ^ 0xff);
        b = (uint8_t)(b & msk[i]);
        if (b != 0) return false;
    }
    return true;
}

std::vector<uint8_t> MaskImpl::complementMask(const std::vector<uint8_t>& msk, std::vector<uint8_t>& results) {
    size_t k = mask.size();
    if (k < msk.size()) k = msk.size();
    for (size_t i = 0; i < k; ++i) {
        uint8_t b;
        if (i < mask.size()) b = (uint8_t)(mask[i] ^ 0xff);
        else b = 0xff;
        if (i < msk.size()) b = (uint8_t)(b & msk[i]);
        else b = 0;
        results[i] = b;
    }
    return results;
}

std::string MaskImpl::toString() const {
    std::ostringstream s;
    s << std::uppercase << std::hex;
    for (uint8_t b : mask) {
        s << std::setw(2) << std::setfill('0') << (int)(b & 0xff);
    }
    return s.str();
}

} // namespace ghidra
