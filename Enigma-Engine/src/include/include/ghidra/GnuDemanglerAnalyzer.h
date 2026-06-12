#pragma once

#include <ghidra/AbstractDemanglerAnalyzer.h>

namespace ghidra {

class GnuDemanglerAnalyzer : public AbstractDemanglerAnalyzer {
public:
    GnuDemanglerAnalyzer();
    virtual ~GnuDemanglerAnalyzer() = default;

    virtual bool canAnalyze(Program* program) const override;
    virtual bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
};

} // namespace ghidra
