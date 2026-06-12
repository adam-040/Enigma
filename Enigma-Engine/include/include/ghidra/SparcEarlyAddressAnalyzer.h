#pragma once

#include <ghidra/SparcAnalyzer.h>

namespace ghidra {

class SparcEarlyAddressAnalyzer : public SparcAnalyzer {
public:
    SparcEarlyAddressAnalyzer();
    ~SparcEarlyAddressAnalyzer() override = default;

    bool added(Program* program, const AddressSetView& set,
               TaskMonitor* monitor, MessageLog& log) override;
};

} // namespace ghidra
