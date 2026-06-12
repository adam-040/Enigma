#pragma once

#include <ghidra/AbstractAnalyzer.h>
#include <string>

namespace ghidra {

class CondenseFillerBytesAnalyzer : public AbstractAnalyzer {
public:
    CondenseFillerBytesAnalyzer();
    ~CondenseFillerBytesAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;

    void registerOptions(Options& options, Program* program) override;
    void optionsChanged(Options& options, Program* program) override;

private:
    std::string determineFillerValue(Program* program) const;
    int countUndefineds(Program* program, Address address, uint8_t fillerByte) const;
    void replaceFillerBytes(Listing* listing, Address address, int length);

    int minBytes_ = 1;
    std::string fillerValue_ = "Auto";
};

} // namespace ghidra
