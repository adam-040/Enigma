#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class HexagonUnsupportSemanticAnalyzer : public AbstractAnalyzer {
public:
    HexagonUnsupportSemanticAnalyzer();
    ~HexagonUnsupportSemanticAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    bool getDefaultEnablement(Program* program) const override;
};

} // namespace ghidra
