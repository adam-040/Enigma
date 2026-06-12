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
/// \brief Program listing implementation
#include <ghidra/Listing.h>
#include <ghidra/Program.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Instruction.h>
#include <ghidra/Data.h>

namespace ghidra {

Listing::Listing(Program* program) : program_(program) {}

Program* Listing::getProgram() const {
    return program_;
}

Instruction* Listing::getInstructionAt(Address addr) const {
    auto it = instructions_.find(addr.toString());
    return (it != instructions_.end()) ? it->second : nullptr;
}

Instruction* Listing::getInstructionContaining(Address addr) const {
    for (const auto& pair : instructions_) {
        Instruction* inst = pair.second;
        if (addr >= inst->getAddress() && addr <= inst->getMaxAddress()) {
            return inst;
        }
    }
    return nullptr;
}

Data* Listing::getDataAt(Address addr) const {
    auto it = data_.find(addr.toString());
    return (it != data_.end()) ? it->second : nullptr;
}

Data* Listing::getDataContaining(Address addr) const {
    for (const auto& pair : data_) {
        Data* d = pair.second;
        if (addr >= d->getAddress() && addr <= d->getMaxAddress()) {
            return d;
        }
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
    if (auto inst = getInstructionAt(addr)) return inst;
    return getDataAt(addr);
}

CodeUnit* Listing::getCodeUnitContaining(Address addr) const {
    if (auto inst = getInstructionContaining(addr)) return inst;
    return getDataContaining(addr);
}

void Listing::addInstruction(Instruction* inst) {
    instructions_[inst->getAddress().toString()] = inst;
}

void Listing::addData(Data* data) {
    data_[data->getAddress().toString()] = data;
}

void Listing::removeInstruction(Address addr) {
    instructions_.erase(addr.toString());
}

void Listing::removeData(Address addr) {
    data_.erase(addr.toString());
}

bool Listing::isUndefined(Address addr) const {
    return !instructions_.count(addr.toString()) && !data_.count(addr.toString());
}

size_t Listing::getInstructionCount() const {
    return instructions_.size();
}

size_t Listing::getDataCount() const {
    return data_.size();
}

std::vector<Instruction*> Listing::getInstructions(const AddressSetView& set) const {
    std::vector<Instruction*> result;
    for (const auto& pair : instructions_) {
        if (set.contains(pair.second->getAddress())) {
            result.push_back(pair.second);
        }
    }
    return result;
}

std::vector<Data*> Listing::getData(const AddressSetView& set) const {
    std::vector<Data*> result;
    for (const auto& pair : data_) {
        if (set.contains(pair.second->getAddress())) {
            result.push_back(pair.second);
        }
    }
    return result;
}

} // namespace ghidra
