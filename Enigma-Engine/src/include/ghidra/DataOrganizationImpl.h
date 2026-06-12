/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataOrganizationImpl.h
/// \brief Concrete standard data organization implementation for 64-bit platform
#pragma once

#include <ghidra/DataOrganization.h>
#include <ghidra/BitFieldPackingImpl.h>
#include <ghidra/DataType.h>
#include <memory>

namespace ghidra {

class DataOrganizationImpl : public DataOrganization {
public:
    DataOrganizationImpl() {
        bitFieldPacking_ = std::make_unique<BitFieldPackingImpl>();
    }

    bool isBigEndian() const override { return false; }
    int getPointerSize() const override { return 8; }
    int getPointerShift() const override { return 0; }
    bool isSignedChar() const override { return true; }
    int getCharSize() const override { return 1; }
    int getWideCharSize() const override { return 4; }
    int getShortSize() const override { return 2; }
    int getIntegerSize() const override { return 4; }
    int getLongSize() const override { return 8; }
    int getLongLongSize() const override { return 8; }
    int getFloatSize() const override { return 4; }
    int getDoubleSize() const override { return 8; }
    int getLongDoubleSize() const override { return 8; }
    int getAbsoluteMaxAlignment() const override { return 8; }
    int getMachineAlignment() const override { return 8; }
    int getDefaultAlignment() const override { return 8; }
    int getDefaultPointerAlignment() const override { return 8; }

    int getSizeAlignment(int size) const override {
        if (size <= 1) return 1;
        if (size <= 2) return 2;
        if (size <= 4) return 4;
        return 8;
    }

    BitFieldPacking* getBitFieldPacking() const override { return bitFieldPacking_.get(); }

    int getSizeAlignmentCount() const override { return 4; }

    std::vector<int> getSizes() const override {
        return {1, 2, 4, 8};
    }

    std::string getIntegerCTypeApproximation(int size, bool is_signed) const override {
        if (size == 1) return is_signed ? "char" : "unsigned char";
        if (size == 2) return is_signed ? "short" : "unsigned short";
        if (size == 4) return is_signed ? "int" : "unsigned int";
        return is_signed ? "long" : "unsigned long";
    }

    int getAlignment(DataType* dataType) const override {
        if (!dataType) return 1;
        int len = dataType->getLength();
        if (len <= 0) return 1;
        return getSizeAlignment(len);
    }

    static int getLeastCommonMultiple(int a, int b) {
        if (a == 0 || b == 0) return 0;
        int x = a, y = b;
        while (y) { int t = y; y = x % y; x = t; }
        return a / x * b;
    }

    static int getAlignedOffset(int alignment, int offset) {
        if (alignment <= 1) return offset;
        int mod = offset % alignment;
        if (mod == 0) return offset;
        return offset + (alignment - mod);
    }

private:
    std::unique_ptr<BitFieldPackingImpl> bitFieldPacking_;
};

} // namespace ghidra
