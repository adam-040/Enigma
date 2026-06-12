#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class ExternalEntryFunctionAnalyzer : public AbstractAnalyzer {
public:
    ExternalEntryFunctionAnalyzer();
    ~ExternalEntryFunctionAnalyzer() override = default;

    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
};

} // namespace ghidra
