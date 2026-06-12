/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 */
/// \file Reference.h
/// \brief Interface for a reference between addresses
#pragma once

#include <cstdint>
#include <memory>
#include <string>

namespace ghidra {

class Address;

class Reference {
public:
    virtual ~Reference() = default;

    virtual std::shared_ptr<Address> getFromAddress() const = 0;
    virtual std::shared_ptr<Address> getToAddress() const = 0;
    virtual int64_t getSymbolID() const = 0;
    virtual bool isExternalReference() const = 0;
    virtual bool isMemoryReference() const = 0;
    virtual bool isOffsetReference() const = 0;
    virtual bool isStackReference() const = 0;
    virtual int getReferenceType() const = 0;
    virtual int getOperandIndex() const = 0;
    virtual std::string getMnemonicRef() const = 0;
    virtual bool isPrimaryPath() const = 0;
};

} // namespace ghidra
