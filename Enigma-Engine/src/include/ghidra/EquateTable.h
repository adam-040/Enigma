/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file EquateTable.h
/// \brief Equate table interface
/// Translated from: ghidra.program.model.symbol.EquateTable
#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace ghidra {

class Equate {
public:
    Equate() = default;
    Equate(const std::string& name, int64_t value) : name_(name), value_(value) {}

    const std::string& getName() const { return name_; }
    int64_t getValue() const { return value_; }

    void setName(const std::string& name) { name_ = name; }

private:
    std::string name_;
    int64_t value_ = 0;
};

class Address;
class HighFunction;
class Encoder;
class Decoder;

class EquateTable {
public:
    virtual ~EquateTable() = default;

    /// One operand reference binding of an equate to (address, operand).
    struct Binding {
        Equate* equate = nullptr;
        uint64_t addressOffset = 0;
        int16_t opIndex = 0;
    };

    virtual Equate* createEquate(const std::string& name, int64_t value) = 0;
    virtual Equate* getEquate(const std::string& name) = 0;
    virtual Equate* getEquate(int64_t value) = 0;
    virtual std::vector<Equate*> getEquates() = 0;
    virtual int getEquateCount() = 0;

    /// Binds an existing equate to an operand reference. Returns false when
    /// the equate is null.
    virtual bool addReference(Equate* equate, const Address& addr, int opndPosition) = 0;
    /// All (equate, address, operand) bindings, one entry per reference.
    virtual std::vector<Binding> getAllBindings() = 0;

    virtual Equate* getEquate(const Address& addr, int opndPosition, int64_t value) = 0;
    virtual std::vector<Equate*> getEquates(const Address& addr, int opndPosition) = 0;
    virtual std::vector<Equate*> getEquates(const Address& addr) = 0;
    virtual void removeEquate(const Address& addr, int opndPosition, int64_t value) = 0;
    virtual void removeEquate(Equate* equate) = 0;
    virtual Equate* createEquate(const std::string& name, int64_t value,
                                 const Address& addr, int opndPosition) = 0;

    /// Save the equates as XML.
    virtual void saveXml(Encoder& encoder, int sourceType) const = 0;
    /// Load equates from XML.
    virtual void decode(Decoder& decoder, HighFunction* func) = 0;
};

} // namespace ghidra
