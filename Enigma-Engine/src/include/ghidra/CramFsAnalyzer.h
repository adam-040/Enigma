#pragma once

#include <ghidra/AbstractAnalyzer.h>
#include <cstdint>

namespace ghidra {

class CramFsAnalyzer : public AbstractAnalyzer {
public:
    CramFsAnalyzer();
    ~CramFsAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    bool getDefaultEnablement(Program* program) const override;

private:
    static constexpr uint32_t CRAMFS_MAGIC = 0x28cd3d45;
    static constexpr int HEADER_STRING_LENGTH = 16;
};

} // namespace ghidra
