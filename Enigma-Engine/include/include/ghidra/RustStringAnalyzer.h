#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class RustStringAnalyzer : public AbstractAnalyzer {
public:
    RustStringAnalyzer();
    ~RustStringAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;

private:
    int getMaxStringLength(Program* program, const Address& address, int maxLen) const;
    void recurseString(Program* program, const Address& start, int maxLen);
};

} // namespace ghidra
