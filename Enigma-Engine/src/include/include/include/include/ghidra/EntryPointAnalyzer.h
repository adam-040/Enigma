#pragma once

#include <ghidra/AbstractAnalyzer.h>
#include <unordered_set>

namespace ghidra {

class EntryPointAnalyzer : public AbstractAnalyzer {
public:
    EntryPointAnalyzer();
    ~EntryPointAnalyzer() override = default;

    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    void registerOptions(Options& options, Program* program) override;
    void optionsChanged(Options& options, Program* program) override;

private:
    void doDisassembly(Program* program, TaskMonitor* monitor, const std::vector<Address>& entries);
    void addExternalEntryPoints(Program* program, const AddressSetView& set, std::vector<Address>& entries);
    void addSymbolEntryPoints(Program* program, const AddressSetView& set, std::vector<Address>& entries);
    void findDummyFunctions(Program* program, const AddressSetView& set, std::vector<Address>& dummySet, std::vector<Address>& redoSet);

    bool respectExecuteFlags_ = true;
};

} // namespace ghidra
