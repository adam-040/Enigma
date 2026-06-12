/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file CodeManager.h
/// \brief Manages code units (instructions and data) in the program
/// Translated from: ghidra.program.database.code.CodeManager
#pragma once

#include <ghidra/Address.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/Instruction.h>
#include <ghidra/Data.h>
#include <ghidra/ManagerDB.h>
#include <unordered_map>
#include <vector>
#include <string>
#include <memory>

namespace ghidra {

class Program;
class TaskMonitor;

class CodeManager : public ManagerDB {
public:
    CodeManager() = default;
    explicit CodeManager(Program* program) : program_(program) {}

    void setProgram(Program* program) override { program_ = program; }
    void programReady(int openMode, int currentRevision, TaskMonitor* monitor) override {}
    void clearCache(bool all) override { if (all) { instructions_.clear(); data_.clear(); } }
    void deleteAddressRange(const Address& startAddr, const Address& endAddr, TaskMonitor* monitor) override;
    void moveAddressRange(const Address& fromAddr, const Address& toAddr, uint64_t length, TaskMonitor* monitor) override {}
    int getNumEntries() override { return static_cast<int>(instructions_.size() + data_.size()); }
    int getRevision() override { return revision_; }
    void setRevision(int revision) override { revision_ = revision; }
    void invalidateCache(bool all) override { clearCache(all); }
    std::string getName() const override { return "CodeManager"; }

    Instruction* getInstructionAt(const Address& addr) const {
        auto it = instructions_.find(addr.toString());
        return (it != instructions_.end()) ? it->second : nullptr;
    }

    Instruction* getInstructionContaining(const Address& addr) const;

    Data* getDataAt(const Address& addr) const {
        auto it = data_.find(addr.toString());
        return (it != data_.end()) ? it->second : nullptr;
    }

    Data* getDataContaining(const Address& addr) const;

    void addInstruction(Instruction* inst) {
        instructions_[inst->getAddress().toString()] = inst;
    }

    void addData(Data* data) {
        data_[data->getAddress().toString()] = data;
    }

    void removeInstruction(const Address& addr) {
        instructions_.erase(addr.toString());
    }

    void removeData(const Address& addr) {
        data_.erase(addr.toString());
    }

    bool isUndefined(const Address& addr) const;

    void activateContextLocking() {}

private:
    Program* program_ = nullptr;
    std::unordered_map<std::string, Instruction*> instructions_;
    std::unordered_map<std::string, Data*> data_;
    int revision_ = 0;
};

} // namespace ghidra
