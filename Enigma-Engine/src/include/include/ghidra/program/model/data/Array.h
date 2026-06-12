/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 */
/// \file Array.h
/// \brief Interface for array data types
#pragma once

#include <memory>

namespace ghidra {

class DataType;

class Array {
public:
    virtual ~Array() = default;

    virtual int getNumElements() const = 0;
    virtual int getLength() const = 0;
    virtual std::shared_ptr<DataType> getDataType() const = 0;
    virtual std::shared_ptr<Array> newArray(int numElements) const = 0;
};

} // namespace ghidra
