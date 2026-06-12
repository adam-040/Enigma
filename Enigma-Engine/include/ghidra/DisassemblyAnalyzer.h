#pragma once

#include <ghidra/AbstractAnalyzer.h>
#include <ghidra/Address.h>
#include <vector>
#include <cstdint>
#include <unordered_set>
#include <queue>

namespace ghidra {

class ProgramDB;

class DisassemblyAnalyzer : public AbstractAnalyzer {
public:
    DisassemblyAnalyzer();
    bool added(Program* program, const AddressSetView& set,
               TaskMonitor* monitor, MessageLog& log) override;
    bool canAnalyze(Program* program) const override;
};

} // namespace ghidra
