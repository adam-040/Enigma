/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DatabaseAdapter.h
/// \brief SQLite database adapter for Program Model persistence
/// Replaces Ghidra's Java DB layer with SQLite
#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <memory>

namespace ghidra {

class ProgramDB;
class Address;
class Symbol;
class Function;
class MemoryBlock;

struct DBResult {
    std::vector<std::vector<std::string>> rows;
    std::vector<std::string> columns;
    int rowCount() const { return static_cast<int>(rows.size()); }
};

class DatabaseAdapter {
public:
    virtual ~DatabaseAdapter() = default;

    virtual bool open(const std::string& filePath, bool createIfMissing = true) = 0;
    virtual void close() = 0;
    virtual bool isOpen() const = 0;

    virtual bool execute(const std::string& sql) = 0;
    virtual DBResult query(const std::string& sql) = 0;

    virtual int64_t lastInsertRowId() const = 0;
    virtual int changes() const = 0;

    virtual bool beginTransaction() = 0;
    virtual bool commitTransaction() = 0;
    virtual bool rollbackTransaction() = 0;

    virtual bool createSchema() = 0;
    virtual bool populateProgram(ProgramDB* program) = 0;
    virtual bool loadProgram(ProgramDB* program) = 0;

    virtual std::string getLastError() const = 0;

protected:
    static std::string escapeString(const std::string& input);
    static int64_t addressToLong(const Address& addr);
    static Address longToAddress(int64_t value);
};

std::unique_ptr<DatabaseAdapter> createDatabaseAdapter();

} // namespace ghidra
