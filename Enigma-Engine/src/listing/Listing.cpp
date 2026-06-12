/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Listing.cpp
/// \brief Program listing - manages instructions and data
#include <ghidra/Listing.h>
#include <ghidra/Program.h>
#include <ghidra/Instruction.h>
#include <ghidra/Data.h>
#include <ghidra/CodeUnit.h>
#include <ghidra/AddressSetView.h>
#include <sstream>

namespace ghidra {

Listing::Listing(Program* program) : program_(program) {}

Program* Listing::getProgram() const { return program_; }

Instruction* Listing::getInstructionAt(Address addr) const {
    std::ostringstream ss;
    ss << addr.toString();
    auto it = instructions_.find(ss.str());
    return (it != instructions_.end()) ? it->second : nullptr;
}

Instruction* Listing::getInstructionContaining(Address addr) const {
    for (const auto& pair : instructions_) {
        if (pair.second && pair.second->getAddress() == addr) return pair.second;
    }
    return nullptr;
}

Data* Listing::getDataAt(Address addr) const {
    std::ostringstream ss;
    ss << addr.toString();
    auto it = data_.find(ss.str());
    return (it != data_.end()) ? it->second : nullptr;
}

Data* Listing::getDataContaining(Address addr) const {
    for (const auto& pair : data_) {
        if (pair.second && pair.second->getAddress() == addr) return pair.second;
    }
    return nullptr;
}

Instruction* Listing::getInstructionAfter(Address addr) const {
    Instruction* found = nullptr;
    for (const auto& pair : instructions_) {
        Instruction* inst = pair.second;
        if (!inst) continue;
        Address instAddr = inst->getAddress();
        if (instAddr > addr) {
            if (!found || instAddr < found->getAddress()) {
                found = inst;
            }
        }
    }
    return found;
}

Data* Listing::getDefinedDataContaining(Address addr) const {
    Data* data = getDataAt(addr);
    if (data && data->isDefined()) return data;
    for (const auto& pair : data_) {
        Data* d = pair.second;
        if (!d || !d->isDefined()) continue;
        Address dAddr = d->getAddress();
        if (dAddr <= addr && addr <= d->getMaxAddress()) {
            return d;
        }
    }
    return nullptr;
}

CodeUnit* Listing::getCodeUnitAt(Address addr) const {
    if (Instruction* inst = getInstructionAt(addr)) return inst;
    return getDataAt(addr);
}

CodeUnit* Listing::getCodeUnitContaining(Address addr) const {
    if (Instruction* inst = getInstructionContaining(addr)) return inst;
    return getDataContaining(addr);
}

void Listing::addInstruction(Instruction* inst) {
    if (!inst) return;
    std::ostringstream ss;
    ss << inst->getAddress().toString();
    instructions_[ss.str()] = inst;
}

Data* Listing::createData(Address addr, DataType* dataType, int length) {
    if (!dataType) return nullptr;
    if (getDataAt(addr) || getInstructionAt(addr)) return nullptr;
    if (length < 0) length = dataType->getLength();
    if (length <= 0) return nullptr;
    Data* data = new Data(getProgram(), addr, dataType, length);
    addData(data);
    return data;
}

void Listing::addData(Data* data) {
    if (!data) return;
    std::ostringstream ss;
    ss << data->getAddress().toString();
    data_[ss.str()] = data;
}

void Listing::removeInstruction(Address addr) {
    std::ostringstream ss;
    ss << addr.toString();
    instructions_.erase(ss.str());
}

void Listing::removeData(Address addr) {
    std::ostringstream ss;
    ss << addr.toString();
    data_.erase(ss.str());
}

bool Listing::isUndefined(Address addr) const {
    return !getInstructionAt(addr) && !getDataAt(addr);
}

size_t Listing::getInstructionCount() const { return instructions_.size(); }
size_t Listing::getDataCount() const { return data_.size(); }

std::vector<Instruction*> Listing::getInstructions(const AddressSetView& set) const {
    std::vector<Instruction*> result;
    for (const auto& pair : instructions_) {
        if (pair.second && set.contains(pair.second->getAddress())) {
            result.push_back(pair.second);
        }
    }
    return result;
}

std::vector<Data*> Listing::getData(const AddressSetView& set) const {
    std::vector<Data*> result;
    for (const auto& pair : data_) {
        if (pair.second && set.contains(pair.second->getAddress())) {
            result.push_back(pair.second);
        }
    }
    return result;
}

} // namespace ghidra
