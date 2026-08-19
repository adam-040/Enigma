/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file EquateTableImpl.h
/// \brief Implementation of equate table
/// Translated from: ghidra.program.database.symbol.EquateTableDB
#pragma once

#include <ghidra/EquateTable.h>
#include <ghidra/ManagerDB.h>
#include <vector>
#include <unordered_map>
#include <memory>
#include <cstdint>

namespace ghidra {

class Program;
class TaskMonitor;
class Address;
class Encoder;
class Decoder;
class HighFunction;

class EquateTableImpl : public EquateTable, public ManagerDB {
public:
    EquateTableImpl() = default;
    explicit EquateTableImpl(Program* program) : program_(program) {}

    void setProgram(Program* program) override { program_ = program; }
    void programReady(int openMode, int currentRevision, TaskMonitor* monitor) override {}
    void clearCache(bool all) override { if (all) { equates_.clear(); equatesByName_.clear(); equatesByValue_.clear(); } }
    void deleteAddressRange(const Address& startAddr, const Address& endAddr, TaskMonitor* monitor) override {}
    void moveAddressRange(const Address& fromAddr, const Address& toAddr, uint64_t length, TaskMonitor* monitor) override {}
    int getNumEntries() override { return getEquateCount(); }
    int getRevision() override { return revision_; }
    void setRevision(int revision) override { revision_ = revision; }
    void invalidateCache(bool all) override { clearCache(all); }
    std::string getName() const override { return "EquateTable"; }

    Equate* createEquate(const std::string& name, int64_t value) override;

    Equate* getEquate(const std::string& name) override;

    Equate* getEquate(int64_t value) override;

    std::vector<Equate*> getEquates() override;

    int getEquateCount() override { return static_cast<int>(equates_.size()); }

    bool addReference(Equate* equate, const Address& addr, int opndPosition) override;
    std::vector<Binding> getAllBindings() override;

    Equate* getEquate(const Address& addr, int opndPosition, int64_t value) override;
    std::vector<Equate*> getEquates(const Address& addr, int opndPosition) override;
    std::vector<Equate*> getEquates(const Address& addr) override;
    void removeEquate(const Address& addr, int opndPosition, int64_t value) override;
    void removeEquate(Equate* equate) override;
    Equate* createEquate(const std::string& name, int64_t value,
                         const Address& addr, int opndPosition) override;
    void saveXml(Encoder& encoder, int sourceType) const override;
    void decode(Decoder& decoder, HighFunction* func) override;

private:
    /// Composite key for an (addr, opnd) occurrence: addr-offset << 8 | opnd.
    using OpndKey = uint64_t;
    static OpndKey makeKey(const Address& addr, int opnd);

    Program* program_ = nullptr;
    std::vector<std::unique_ptr<Equate>> equates_;
    std::unordered_map<std::string, Equate*> equatesByName_;
    std::unordered_map<int64_t, Equate*> equatesByValue_;
    std::unordered_map<OpndKey, std::vector<Equate*>> opndRefs_;
    int revision_ = 0;
};

} // namespace ghidra
