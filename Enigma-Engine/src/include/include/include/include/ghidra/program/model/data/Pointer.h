/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 */
/// \file Pointer.h
/// \brief Interface for pointer data types
#pragma once

#include <memory>

namespace ghidra {

class DataType;
class Address;

class Pointer {
public:
    virtual ~Pointer() = default;

    virtual std::shared_ptr<DataType> getDataType() const = 0;
    virtual int getLength() const = 0;
    virtual bool isConstant() const = 0;
    virtual bool isPointer() const { return true; }
    virtual bool isUndefined() const = 0;
};

} // namespace ghidra
