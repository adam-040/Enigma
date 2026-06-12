#pragma once

#include <ghidra/SharedReturnAnalyzer.h>

namespace ghidra {

class SharedReturnJumpAnalyzer : public SharedReturnAnalyzer {
public:
    SharedReturnJumpAnalyzer();
    virtual ~SharedReturnJumpAnalyzer() = default;

    virtual bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
};

} // namespace ghidra
