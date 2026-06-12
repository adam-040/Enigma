#pragma once

#include <ghidra/SH4AddressAnalyzer.h>

namespace ghidra {

class SH4EarlyAddressAnalyzer : public SH4AddressAnalyzer {
public:
    SH4EarlyAddressAnalyzer();
    ~SH4EarlyAddressAnalyzer() override = default;

    AddressSet flowConstants(Program* program, const Address& flowStart,
                             const AddressSetView* flowSet, SymbolicPropogator* symEval,
                             TaskMonitor* monitor) override;
};

} // namespace ghidra
