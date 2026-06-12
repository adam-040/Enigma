#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class CFStringAnalyzer : public AbstractAnalyzer {
public:
    CFStringAnalyzer();
    ~CFStringAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    bool getDefaultEnablement(Program* program) const override;

private:
    std::string makeComment(const std::string& str) const;
    std::string makeLabel(const std::string& str) const;
    bool doesStringContainAllSameChars(const std::string& str) const;
    bool isMachOAndContainsCFStrings(Program* program) const;
};

} // namespace ghidra
