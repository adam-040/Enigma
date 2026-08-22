#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class GuardCfgAnalyzer : public AbstractAnalyzer {
public:
    GuardCfgAnalyzer();
    virtual ~GuardCfgAnalyzer() = default;

    virtual bool canAnalyze(Program* program) const override;
    virtual bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
};

} // namespace ghidra
