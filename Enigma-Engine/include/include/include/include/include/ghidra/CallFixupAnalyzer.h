#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class CallFixupAnalyzer : public AbstractAnalyzer {
public:
    CallFixupAnalyzer();
    virtual ~CallFixupAnalyzer() = default;

protected:
    CallFixupAnalyzer(const std::string& name, AnalyzerType type, bool supportsOneTime);

public:
    virtual bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
};

} // namespace ghidra
