#pragma once

#include <ghidra/AbstractAnalyzer.h>
#include <string>
#include <vector>

namespace ghidra {

class WindowsResourceReferenceAnalyzer : public AbstractAnalyzer {
public:
    WindowsResourceReferenceAnalyzer();
    virtual ~WindowsResourceReferenceAnalyzer() = default;

    virtual bool canAnalyze(Program* program) const override;
    virtual void registerOptions(Options& options, Program* program) override;
    virtual void optionsChanged(Options& options, Program* program) override;
    virtual bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;

private:
    long long findResourceIdImmediate(const std::vector<Instruction*>& sortedInstrs,
                                      const Address& callAddr, int paramIndex);
    Address findResourceAddress(SymbolTable* symTable, const std::string& prefix,
                                long long resourceId);
    std::string toHexString(long long value) const;

    bool createBookmarksEnabled_ = true;
};

} // namespace ghidra
