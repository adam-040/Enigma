#pragma once
#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class DataRefFunctionAnalyzer : public AbstractAnalyzer {
public:
    DataRefFunctionAnalyzer();
    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set,
               TaskMonitor* monitor, MessageLog& log) override;
};

} // namespace ghidra
