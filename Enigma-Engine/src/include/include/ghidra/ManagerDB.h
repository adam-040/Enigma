/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ManagerDB.h
/// \brief Database manager interface for program components
/// Translated from: ghidra.program.database.ManagerDB
#pragma once

#include <ghidra/Address.h>
#include <ghidra/AddressSetView.h>
#include <cstdint>

namespace ghidra {

class Program;
class TaskMonitor;

class ManagerDB {
public:
    static constexpr int NO_MANAGER = -1;

    virtual ~ManagerDB() = default;

    virtual void setProgram(Program* program) = 0;
    virtual void programReady(int openMode, int currentRevision, TaskMonitor* monitor) = 0;
    virtual void clearCache(bool all) = 0;
    virtual void deleteAddressRange(const Address& startAddr, const Address& endAddr, TaskMonitor* monitor) = 0;
    virtual void moveAddressRange(const Address& fromAddr, const Address& toAddr, uint64_t length, TaskMonitor* monitor) = 0;
    virtual int getNumEntries() = 0;
    virtual int getRevision() = 0;
    virtual void setRevision(int revision) = 0;
    virtual void invalidateCache(bool all) = 0;
    virtual std::string getName() const = 0;
};

} // namespace ghidra
