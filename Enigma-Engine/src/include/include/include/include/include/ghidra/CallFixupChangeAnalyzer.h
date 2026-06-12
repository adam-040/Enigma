#pragma once

#include <ghidra/CallFixupAnalyzer.h>

namespace ghidra {

class CallFixupChangeAnalyzer : public CallFixupAnalyzer {
public:
    CallFixupChangeAnalyzer();
    virtual ~CallFixupChangeAnalyzer() = default;

    virtual bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
};

} // namespace ghidra
