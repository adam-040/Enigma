/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file CodeManager.cpp
/// \brief Manages code units (instructions and data) in the program
/// Translated from: ghidra.program.database.code.CodeManager

#include <ghidra/CodeManager.h>

namespace ghidra {

void CodeManager::deleteAddressRange(const Address& startAddr, const Address& endAddr, TaskMonitor* monitor) {
    auto it = instructions_.begin();
    while (it != instructions_.end()) {
        if (it->second->getAddress() >= startAddr && it->second->getAddress() <= endAddr) {
            it = instructions_.erase(it);
        } else {
            ++it;
        }
    }
    auto dit = data_.begin();
    while (dit != data_.end()) {
        if (dit->second->getAddress() >= startAddr && dit->second->getAddress() <= endAddr) {
            dit = data_.erase(dit);
        } else {
            ++dit;
        }
    }
}

Instruction* CodeManager::getInstructionContaining(const Address& addr) const {
    for (const auto& pair : instructions_) {
        Instruction* inst = pair.second;
        if (addr >= inst->getAddress() && addr <= inst->getMaxAddress()) {
            return inst;
        }
    }
    return nullptr;
}

Data* CodeManager::getDataContaining(const Address& addr) const {
    for (const auto& pair : data_) {
        Data* d = pair.second;
        if (addr >= d->getAddress() && addr <= d->getMaxAddress()) {
            return d;
        }
    }
    return nullptr;
}

bool CodeManager::isUndefined(const Address& addr) const {
    return !instructions_.count(addr.toString()) && !data_.count(addr.toString());
}

} // namespace ghidra
