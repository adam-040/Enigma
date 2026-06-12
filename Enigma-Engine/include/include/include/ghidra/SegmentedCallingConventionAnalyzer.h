#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class SegmentedCallingConventionAnalyzer : public AbstractAnalyzer {
public:
    SegmentedCallingConventionAnalyzer();
    virtual ~SegmentedCallingConventionAnalyzer() = default;

    bool canAnalyze(Program* program) const override;
    virtual bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
};

} // namespace ghidra
