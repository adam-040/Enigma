#pragma once

#include <ghidra/AbstractDemanglerAnalyzer.h>

namespace ghidra {

class RustDemanglerAnalyzer : public AbstractDemanglerAnalyzer {
public:
    RustDemanglerAnalyzer();
    virtual ~RustDemanglerAnalyzer() = default;

    virtual bool canAnalyze(Program* program) const override;
    virtual bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
};

} // namespace ghidra
