#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class TEBAnalyzer : public AbstractAnalyzer {
public:
    TEBAnalyzer();
    virtual ~TEBAnalyzer() = default;

    virtual bool canAnalyze(Program* program) const override;
    virtual void registerOptions(Options& options, Program* program) override;
    virtual void optionsChanged(Options& options, Program* program) override;
    virtual bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;

private:
    Address findTEBAddress(Program* program, bool is64Bit, int blockSize);

    std::string tebAddressString_;
    std::string winVersion_;
};

} // namespace ghidra
