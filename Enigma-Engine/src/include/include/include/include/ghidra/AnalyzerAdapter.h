#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class AnalyzerAdapter : public AbstractAnalyzer {
public:
    AnalyzerAdapter(const std::string& name, const AnalysisPriority& priority)
        : AbstractAnalyzer(name, "", AnalyzerType::INSTRUCTION_ANALYZER) {
        setPriority(priority);
        setDefaultEnablement(false);
    }

    bool added(Program* program, const AddressSetView& set,
               TaskMonitor* monitor, MessageLog& log) override {
        return false;
    }
};

} // namespace ghidra
