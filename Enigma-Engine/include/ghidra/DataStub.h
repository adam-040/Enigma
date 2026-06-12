/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataStub.h
/// \brief Stub Data that throws on all operations
/// Translated from: ghidra.program.model.listing.DataStub
#pragma once

#include <ghidra/Address.h>
#include <string>

namespace ghidra {

class Program;
class DataType;
class Memory;
class Reference;

class DataStub {
public:
    DataStub() = default;

    Program* getProgram() const;
    Address getAddress() const;
    int getLength() const;

    Memory* getMemory() const;

    DataType* getDataType() const;
    std::string getComment() const;
    void setComment(const std::string& c);
    std::string toString() const;
};

} // namespace ghidra
