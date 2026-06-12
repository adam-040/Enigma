#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class HCS12ConventionAnalyzer : public AbstractAnalyzer {
public:
    HCS12ConventionAnalyzer();
    ~HCS12ConventionAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;

private:
    void checkReturn(Program* program, Instruction* instr);
    void setPrototypeModel(Program* program, Instruction* instr, const std::string& convention);
};

} // namespace ghidra
