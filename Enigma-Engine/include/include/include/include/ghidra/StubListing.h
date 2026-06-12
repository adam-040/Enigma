/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file StubListing.h
/// \brief Stub Listing that throws on most operations
/// Translated from: ghidra.program.model.listing.StubListing
#pragma once

#include <ghidra/Address.h>
#include <ghidra/AddressSet.h>
#include <string>
#include <vector>

namespace ghidra {

class Program;
class Instruction;
class Data;
class CodeUnit;
class DataType;
class AddressSetView;
class AddressRangeIterator;

class StubListing {
public:
    StubListing() = default;

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

    AddressRangeIterator* getCommentAddressIterator(const AddressSetView& set, bool forward) const;
    int getCommentAddressCount(const AddressSetView& set) const;
    std::string getComment(Address addr, int commentType) const;
};

} // namespace ghidra
