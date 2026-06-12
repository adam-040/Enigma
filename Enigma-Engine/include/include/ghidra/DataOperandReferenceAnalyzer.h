#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class DataOperandReferenceAnalyzer : public AbstractAnalyzer {
public:
    DataOperandReferenceAnalyzer();
    ~DataOperandReferenceAnalyzer() override = default;

    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
};

} // namespace ghidra
