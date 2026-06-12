#pragma once

#include <ghidra/FunctionTagManager.h>
#include <ghidra/FunctionTagImpl.h>
#include <ghidra/ManagerDB.h>
#include <memory>
#include <vector>

namespace ghidra {

class Program;

class FunctionTagManagerImpl : public FunctionTagManager, public ManagerDB {
public:
    FunctionTagManagerImpl() = default;
    explicit FunctionTagManagerImpl(Program* program);
    ~FunctionTagManagerImpl() override = default;

    // ManagerDB interface
    void setProgram(Program* program) override { program_ = program; }
    void programReady(int openMode, int currentRevision, TaskMonitor* monitor) override {}
    void clearCache(bool all) override { if (all) { tags_.clear(); } }
    void deleteAddressRange(const Address& startAddr, const Address& endAddr, TaskMonitor* monitor) override {}
    void moveAddressRange(const Address& fromAddr, const Address& toAddr, uint64_t length, TaskMonitor* monitor) override {}
    int getNumEntries() override { return static_cast<int>(tags_.size()); }
    int getRevision() override { return revision_; }
    void setRevision(int revision) override { revision_ = revision; }
    void invalidateCache(bool all) override { clearCache(all); }
    std::string getName() const override { return "FunctionTagManager"; }

    // FunctionTagManager interface
    FunctionTag* getFunctionTag(const std::string& name) override;
    FunctionTag* getFunctionTag(long id) override;
    std::vector<FunctionTag*> getAllFunctionTags() override;
    bool isTagAssigned(const std::string& name) override;
    FunctionTag* createFunctionTag(const std::string& name, const std::string& comment) override;
    int getUseCount(FunctionTag* tag) override;
    void removeFunctionTag(long id) override;

    // Helper for DB loading
    FunctionTag* addTagWithId(long id, const std::string& name, const std::string& comment);

private:
    Program* program_ = nullptr;
    std::vector<std::unique_ptr<FunctionTagImpl>> tags_;
    long nextId_ = 1;
    int revision_ = 0;
};

} // namespace ghidra
