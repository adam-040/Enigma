#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class AbstractDemanglerAnalyzer : public AbstractAnalyzer {
public:
    AbstractDemanglerAnalyzer(const std::string& name, const std::string& description);
    virtual ~AbstractDemanglerAnalyzer() = default;

    virtual bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
};

} // namespace ghidra
