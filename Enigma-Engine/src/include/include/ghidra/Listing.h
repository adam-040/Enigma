/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Listing.h
/// \brief Program listing - manages instructions and data
/// Translated from: ghidra.program.model.listing.Listing
#pragma once

#include <ghidra/Address.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/Instruction.h>
#include <ghidra/Data.h>
#include <vector>
#include <string>
#include <unordered_map>

namespace ghidra {

class Program;

class Listing {
public:
    Listing() = default;
    explicit Listing(Program* program);

    Program* getProgram() const;

    Instruction* getInstructionAt(Address addr) const;
    Instruction* getInstructionContaining(Address addr) const;
    Instruction* getInstructionAfter(Address addr) const;
    Data* getDataAt(Address addr) const;
    Data* getDataContaining(Address addr) const;
    Data* getDefinedDataContaining(Address addr) const;
    CodeUnit* getCodeUnitAt(Address addr) const;
    CodeUnit* getCodeUnitContaining(Address addr) const;

    void addInstruction(Instruction* inst);
    void addData(Data* data);
    Data* createData(Address addr, DataType* dataType, int length = -1);
    void removeInstruction(Address addr);
    void removeData(Address addr);

    bool isUndefined(Address addr) const;
    size_t getInstructionCount() const;
    size_t getDataCount() const;

    std::vector<Instruction*> getInstructions(const AddressSetView& set) const;
    std::vector<Data*> getData(const AddressSetView& set) const;

private:
    Program* program_ = nullptr;
    std::unordered_map<std::string, Instruction*> instructions_;
    std::unordered_map<std::string, Data*> data_;
};

} // namespace ghidra
