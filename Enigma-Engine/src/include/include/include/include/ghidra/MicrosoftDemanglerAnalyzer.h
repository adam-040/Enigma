#pragma once

#include <ghidra/AbstractDemanglerAnalyzer.h>

namespace ghidra {

class MicrosoftDemanglerAnalyzer : public AbstractDemanglerAnalyzer {
public:
    MicrosoftDemanglerAnalyzer();
    virtual ~MicrosoftDemanglerAnalyzer() = default;

    virtual bool canAnalyze(Program* program) const override;
    virtual bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
};

} // namespace ghidra
