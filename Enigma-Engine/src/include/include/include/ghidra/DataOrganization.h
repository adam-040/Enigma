/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataOrganization.h
/// \brief Defines architecture/compiler specific size and alignment rules for data types
#pragma once

#include <string>
#include <vector>
#include "BitFieldPacking.h"

namespace ghidra {

class DataType;
/**
 * Interface for data organization parameters (endianness, pointer sizes, 
 * primitive sizes, alignments, etc.).
 * Translated from: ghidra.program.model.data.DataOrganization
 */
class DataOrganization {
public:
    static constexpr int NO_MAXIMUM_ALIGNMENT = 0;

    virtual ~DataOrganization() = default;

    /// @return true if data stored big-endian byte order
    virtual bool isBigEndian() const = 0;

    /// @return the size of a pointer data type in bytes.
    virtual int getPointerSize() const = 0;

    /// @return the left shift amount for shifted-pointers.
    virtual int getPointerShift() const = 0;

    /// @return true if the "char" type is signed
    virtual bool isSignedChar() const = 0;

    /// @return the size of a char (char) primitive data type in bytes.
    virtual int getCharSize() const = 0;

    /// @return the size of a wide-char (wchar_t) primitive data type in bytes.
    virtual int getWideCharSize() const = 0;

    /// @return the size of a short primitive data type in bytes.
    virtual int getShortSize() const = 0;

    /// @return the size of a int primitive data type in bytes.
    virtual int getIntegerSize() const = 0;

    /// @return the size of a long primitive data type in bytes.
    virtual int getLongSize() const = 0;

    /// @return the size of a long long primitive data type in bytes.
    virtual int getLongLongSize() const = 0;

    /// @return the encoding size of a float primitive data type in bytes.
    virtual int getFloatSize() const = 0;

    /// @return the encoding size of a double primitive data type in bytes.
    virtual int getDoubleSize() const = 0;

    /// @return the encoding size of a long double primitive data type in bytes.
    virtual int getLongDoubleSize() const = 0;

    /// Gets the maximum alignment value that is allowed by this data organization.
    virtual int getAbsoluteMaxAlignment() const = 0;

    /// Gets the maximum useful alignment for the target machine
    virtual int getMachineAlignment() const = 0;

    /// Gets the default alignment to be used for any data type
    virtual int getDefaultAlignment() const = 0;

    /// Gets the default alignment to be used for a pointer that doesn't have size.
    virtual int getDefaultPointerAlignment() const = 0;

    /// Gets the primitive data alignment that is defined for the specified size.
    virtual int getSizeAlignment(int size) const = 0;

    /// Get the composite bitfield packing information associated with this data organization.
    virtual BitFieldPacking* getBitFieldPacking() const = 0;

    /// Gets the number of sizes that have an alignment specified.
    virtual int getSizeAlignmentCount() const = 0;

    /// Gets the ordered list of sizes that have an alignment specified.
    virtual std::vector<int> getSizes() const = 0;

    /// Returns the best fitting integer C-type
    virtual std::string getIntegerCTypeApproximation(int size, bool is_signed) const = 0;

    /// Determines the alignment value for the indicated data type.
    virtual int getAlignment(DataType* dataType) const = 0;

    /// Determine if this DataOrganization is equivalent to another specific instance
    virtual bool isEquivalent(const DataOrganization* obj) const;
};

} // namespace ghidra
