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
#include <algorithm>

namespace ghidra {

Listing::Listing(Program* program) : program_(program) {}

Program* Listing::getProgram() const {
    return program_;
}

Instruction* Listing::getInstructionAt(Address addr) const {
    getPerfCounters().getInstructionAt_calls++;
    auto it = instructions_.find(static_cast<uint64_t>(addr.getOffset()));
    return (it != instructions_.end()) ? it->second : nullptr;
}

void Listing::rebuildSortedInstructions() const {
    sortedInstructions_.clear();
    sortedInstructions_.reserve(instructions_.size());
    for (const auto& pair : instructions_) {
        sortedInstructions_.push_back(pair.second);
    }
    std::sort(sortedInstructions_.begin(), sortedInstructions_.end(),
        [](Instruction* a, Instruction* b) {
            return a->getAddress() < b->getAddress();
        });
    instructionsDirty_ = false;
}

void Listing::rebuildSortedData() const {
    sortedData_.clear();
    sortedData_.reserve(data_.size());
    for (const auto& pair : data_) {
        sortedData_.push_back(pair.second);
    }
    std::sort(sortedData_.begin(), sortedData_.end(),
        [](Data* a, Data* b) {
            return a->getAddress() < b->getAddress();
        });
    dataDirty_ = false;
}

Instruction* Listing::getInstructionContaining(Address addr) const {
    getPerfCounters().getInstructionContaining_calls++;
    if (instructions_.empty()) return nullptr;
    if (instructionsDirty_) rebuildSortedInstructions();

    auto it = std::upper_bound(sortedInstructions_.begin(), sortedInstructions_.end(), addr,
        [](const Address& addr, Instruction* inst) {
            return addr < inst->getAddress();
        });

    if (it != sortedInstructions_.begin()) {
        --it;
        if (addr >= (*it)->getAddress() && addr <= (*it)->getMaxAddress()) {
            return *it;
        }
    }
    return nullptr;
}

Data* Listing::getDataContaining(Address addr) const {
    getPerfCounters().getDataContaining_calls++;
    if (data_.empty()) return nullptr;
    if (dataDirty_) rebuildSortedData();

    auto it = std::upper_bound(sortedData_.begin(), sortedData_.end(), addr,
        [](const Address& addr, Data* d) {
            return addr < d->getAddress();
        });

    if (it != sortedData_.begin()) {
        --it;
        if (addr >= (*it)->getAddress() && addr <= (*it)->getMaxAddress()) {
            return *it;
        }
    }
    return nullptr;
}

Instruction* Listing::getInstructionAfter(Address addr) const {
    if (instructions_.empty()) return nullptr;
    if (instructionsDirty_) rebuildSortedInstructions();

    auto it = std::upper_bound(sortedInstructions_.begin(), sortedInstructions_.end(), addr,
        [](const Address& addr, Instruction* inst) {
            return addr < inst->getAddress();
        });

    return (it != sortedInstructions_.end()) ? *it : nullptr;
}

Data* Listing::getDefinedDataContaining(Address addr) const {
    Data* data = getDataAt(addr);
    if (data && data->isDefined()) return data;
    if (data_.empty()) return nullptr;
    if (dataDirty_) rebuildSortedData();

    auto it = std::upper_bound(sortedData_.begin(), sortedData_.end(), addr,
        [](const Address& addr, Data* d) {
            return addr < d->getAddress();
        });

    if (it != sortedData_.begin()) {
        --it;
        if (addr >= (*it)->getAddress() && addr <= (*it)->getMaxAddress() && (*it)->isDefined()) {
            return *it;
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

Data* Listing::getDataAt(Address addr) const {
    getPerfCounters().getDataAt_calls++;
    auto it = data_.find(static_cast<uint64_t>(addr.getOffset()));
    return (it != data_.end()) ? it->second : nullptr;
}

void Listing::addInstruction(Instruction* inst) {
    getPerfCounters().addInstruction_calls++;
    instructions_[static_cast<uint64_t>(inst->getAddress().getOffset())] = inst;
    instructionsDirty_ = true;
}

void Listing::addData(Data* data) {
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
        if (set.contains(pair.second->getAddress())) {
            result.push_back(pair.second);
        }
    }
    return result;
}

} // namespace ghidra
