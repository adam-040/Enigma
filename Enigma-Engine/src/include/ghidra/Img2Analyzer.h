#pragma once

#include <ghidra/AbstractAnalyzer.h>
#include <cstdint>

namespace ghidra {

class Img2Analyzer : public AbstractAnalyzer {
public:
    Img2Analyzer();
    ~Img2Analyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    bool getDefaultEnablement(Program* program) const override;

private:
    static constexpr uint32_t IMG2_SIGNATURE_INT = 0x32676D49; // bytes: '2','g','m','I' @ offset 0
    static constexpr int IMG2_HEADER_LENGTH = 0x400;
};

} // namespace ghidra
