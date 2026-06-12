#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class AbstractBinaryFormatAnalyzer : public AbstractAnalyzer {
public:
    AbstractBinaryFormatAnalyzer(const std::string& name, const std::string& description);
    virtual ~AbstractBinaryFormatAnalyzer() = default;

    virtual bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
};

} // namespace ghidra
