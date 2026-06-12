/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SymbolManager.h
/// \brief Manages symbols in the program
/// Translated from: ghidra.program.database.symbol.SymbolManager
#pragma once

#include <ghidra/SymbolTable.h>
#include <ghidra/ManagerDB.h>

namespace ghidra {

class Program;
class TaskMonitor;

class SymbolManager : public ManagerDB {
public:
    SymbolManager() = default;
    explicit SymbolManager(SymbolTable* symbolTable) : symbolTable_(symbolTable) {}

    void setProgram(Program* program) override { program_ = program; }
    void programReady(int openMode, int currentRevision, TaskMonitor* monitor) override {}
    void clearCache(bool all) override {}
    void deleteAddressRange(const Address& startAddr, const Address& endAddr, TaskMonitor* monitor) override {}
    void moveAddressRange(const Address& fromAddr, const Address& toAddr, uint64_t length, TaskMonitor* monitor) override {}
    int getNumEntries() override;
    int getRevision() override { return revision_; }
    void setRevision(int revision) override { revision_ = revision; }
    void invalidateCache(bool all) override {}
    std::string getName() const override { return "SymbolManager"; }

    SymbolTable* getSymbolTable() const { return symbolTable_; }

private:
    Program* program_ = nullptr;
    SymbolTable* symbolTable_ = nullptr;
    int revision_ = 0;
};

} // namespace ghidra
