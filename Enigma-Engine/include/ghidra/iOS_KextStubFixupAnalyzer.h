#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class iOS_KextStubFixupAnalyzer : public AbstractAnalyzer {
public:
    iOS_KextStubFixupAnalyzer();
    ~iOS_KextStubFixupAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    bool getDefaultEnablement(Program* program) const override;
};

} // namespace ghidra
