#pragma once

#include <ghidra/AbstractAnalyzer.h>
#include <cstdint>

namespace ghidra {

class Img3Analyzer : public AbstractAnalyzer {
public:
    Img3Analyzer();
    ~Img3Analyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    bool getDefaultEnablement(Program* program) const override;

private:
    static constexpr uint32_t IMG3_SIGNATURE_INT = 0x33676D49; // bytes: '3','g','m','I' @ offset 0
};

} // namespace ghidra
