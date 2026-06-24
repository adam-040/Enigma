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
#include <algorithm>

namespace ghidra {

Listing::Listing(Program* program) : program_(program) {}

Program* Listing::getProgram() const { return program_; }

Instruction* Listing::getInstructionAt(Address addr) const {
    auto it = instructions_.find(static_cast<uint64_t>(addr.getOffset()));
    return (it != instructions_.end()) ? it->second : nullptr;
}

void Listing::rebuildSortedInstructions() const {
    sortedInstructions_.clear();
    sortedInstructions_.reserve(instructions_.size());
    for (const auto& pair : instructions_) {
        if (pair.second) sortedInstructions_.push_back(pair.second);
    }
    std::sort(sortedInstructions_.begin(), sortedInstructions_.end(),
        [](const Instruction* a, const Instruction* b) {
            return a->getMinAddress() < b->getMinAddress();
        });
    instructionsDirty_ = false;
}

void Listing::rebuildSortedData() const {
    sortedData_.clear();
    sortedData_.reserve(data_.size());
    for (const auto& pair : data_) {
        if (pair.second) sortedData_.push_back(pair.second);
    }
    std::sort(sortedData_.begin(), sortedData_.end(),
        [](const Data* a, const Data* b) {
            return a->getAddress() < b->getAddress();
        });
    dataDirty_ = false;
}

Instruction* Listing::getInstructionContaining(Address addr) const {
    ++perfCounters_.getInstructionContaining_calls;
    if (instructionsDirty_) rebuildSortedInstructions();
    auto it = std::upper_bound(sortedInstructions_.begin(), sortedInstructions_.end(), addr,
        [](const Address& a, const Instruction* inst) {
            return a < inst->getMinAddress();
        });
    if (it == sortedInstructions_.begin()) return nullptr;
    --it;
    Instruction* inst = *it;
    if (inst->getMinAddress() <= addr && addr <= inst->getMaxAddress())
        return inst;
    return nullptr;
}

Data* Listing::getDataAt(Address addr) const {
    auto it = data_.find(static_cast<uint64_t>(addr.getOffset()));
    return (it != data_.end()) ? it->second : nullptr;
}

Data* Listing::getDataContaining(Address addr) const {
    if (dataDirty_) rebuildSortedData();
    auto it = std::upper_bound(sortedData_.begin(), sortedData_.end(), addr,
        [](const Address& a, const Data* d) {
            return a < d->getAddress();
        });
    if (it == sortedData_.begin()) return nullptr;
    --it;
    Data* d = *it;
    if (d->getAddress() <= addr && addr <= d->getMaxAddress())
        return d;
    return nullptr;
}

Instruction* Listing::getInstructionAfter(Address addr) const {
    if (instructionsDirty_) rebuildSortedInstructions();
    auto it = std::upper_bound(sortedInstructions_.begin(), sortedInstructions_.end(), addr,
        [](const Address& a, const Instruction* inst) {
            return a < inst->getMinAddress();
        });
    return (it != sortedInstructions_.end()) ? *it : nullptr;
}

Data* Listing::getDefinedDataContaining(Address addr) const {
    Data* data = getDataAt(addr);
    if (data && data->isDefined()) return data;
    if (dataDirty_) rebuildSortedData();
    auto it = std::upper_bound(sortedData_.begin(), sortedData_.end(), addr,
        [](const Address& a, const Data* d) {
            return a < d->getAddress();
        });
    if (it == sortedData_.begin()) return nullptr;
    --it;
    Data* d = *it;
    if (d->getAddress() <= addr && addr <= d->getMaxAddress() && d->isDefined())
        return d;
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
    instructions_[static_cast<uint64_t>(inst->getAddress().getOffset())] = inst;
    instructionsDirty_ = true;
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
    data_[static_cast<uint64_t>(data->getAddress().getOffset())] = data;
    dataDirty_ = true;
}

void Listing::removeInstruction(Address addr) {
    instructions_.erase(static_cast<uint64_t>(addr.getOffset()));
    instructionsDirty_ = true;
}

void Listing::removeData(Address addr) {
    data_.erase(static_cast<uint64_t>(addr.getOffset()));
    dataDirty_ = true;
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

std::vector<Instruction*> Listing::getAllInstructions() const {
    std::vector<Instruction*> result;
    result.reserve(instructions_.size());
    for (const auto& pair : instructions_) {
        if (pair.second) result.push_back(pair.second);
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
